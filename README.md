import csv
import os
import ssl

from ldap3 import (
    Server,
    Connection,
    Tls,
    ALL,
    SUBTREE,
    MODIFY_REPLACE,
    NTLM,
)
from ldap3.utils.conv import escape_filter_chars


LDAP_HOST = os.environ["LDAP_HOST"]
LDAP_PORT = int(os.getenv("LDAP_PORT", "636"))

LDAP_USER = os.environ["LDAP_USER"]
LDAP_PASSWORD = os.environ["LDAP_PASSWORD"]

GROUP_BASE_DN = os.environ["GROUP_BASE_DN"]

GROUP_CN = "GL_FT_AERO"


def connect():
    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        ca_certs_file=os.environ["LDAP_CA_CERT"],
    )

    server = Server(
        LDAP_HOST,
        port=LDAP_PORT,
        use_ssl=True,
        tls=tls,
        get_info=ALL,
    )

    conn = Connection(
        server,
        user=LDAP_USER,
        password=LDAP_PASSWORD,
        authentication=NTLM,
        auto_bind=True,
    )

    return conn


def read_iics_file(path):
    members = []
    wd_values = []

    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        for row in reader:
            member_dn = (row.get("MEMBER_DN") or "").strip()
            wd_termination = (row.get("WD_TERMINATION") or "").strip()

            if member_dn:
                members.append(member_dn)

            if wd_termination:
                wd_values.append(wd_termination)

    # LDAP multi-valued attributes cannot contain duplicate values
    members = list(dict.fromkeys(members))

    distinct_wd_values = list(dict.fromkeys(wd_values))

    if len(distinct_wd_values) > 1:
        raise RuntimeError(
            f"Multiple WD_TERMINATION values found: "
            f"{distinct_wd_values}"
        )

    wd_termination = (
        distinct_wd_values[0]
        if distinct_wd_values
        else None
    )

    return wd_termination, members


def find_group(conn, cn):
    search_filter = (
        f"(&(objectClass=group)"
        f"(cn={escape_filter_chars(cn)}))"
    )

    conn.search(
        search_base=GROUP_BASE_DN,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=[
            "cn",
            "distinguishedName",
            "extensionAttribute3",
            "member",
        ],
    )

    if len(conn.entries) == 0:
        return None

    if len(conn.entries) > 1:
        raise RuntimeError(
            f"More than one group found for cn={cn}"
        )

    return conn.entries[0]


def update_group(
    conn,
    group_dn,
    wd_termination,
    members,
):
    changes = {}

    #
    # Equivalent to:
    #
    # WD_TERMINATION
    #      ->
    # extensionAttribute3
    #
    if wd_termination is not None:
        changes["extensionAttribute3"] = [
            (MODIFY_REPLACE, [wd_termination])
        ]

    #
    # Equivalent to PowerCenter child
    # Update_Strategy_member = 3
    #
    # REPLACE THE COMPLETE MEMBER LIST
    #
    changes["member"] = [
        (MODIFY_REPLACE, members)
    ]

    if not conn.modify(group_dn, changes):
        raise RuntimeError(
            f"LDAP modification failed: {conn.result}"
        )

    print(
        f"Successfully updated {group_dn}; "
        f"members={len(members)}; "
        f"WD_TERMINATION={wd_termination}"
    )


def main():
    input_file = os.environ.get(
        "INPUT_FILE",
        "GL_FT_AERO.csv",
    )

    wd_termination, members = read_iics_file(
        input_file
    )

    #
    # Important safety control.
    #
    # PowerCenter appears to REPLACE member,
    # therefore an empty file could wipe the group.
    #
    if not members:
        raise RuntimeError(
            "No MEMBER_DN values received. "
            "Refusing to replace AD membership with an empty list."
        )

    conn = connect()

    try:
        group = find_group(conn, GROUP_CN)

        if group is None:
            raise RuntimeError(
                f"{GROUP_CN} does not exist. "
                "Current mapping uses UPDATE ELSE INSERT, "
                "but group creation requires the current "
                "sAMAccountName/groupType configuration "
                "before implementing the insert branch."
            )

        group_dn = group.entry_dn

        print(f"Target group: {group_dn}")
        print(f"New member count: {len(members)}")

        update_group(
            conn,
            group_dn,
            wd_termination,
            members,
        )

    finally:
        conn.unbind()


if __name__ == "__main__":
    main()
