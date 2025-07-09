from tabulate import tabulate

controls = [
    {
        "Control": "1.1 – IDOR",
        "References": "OWASP WSTG-ATHZ-04 ",
    },
    {
        "Control": "1.2 – Session & Cookie Mgmt",
        "References": "OWASP WSTG-SESS-02/03 ",
    },
    {
        "Control": "1.3 – State & Race Conditions",
        "References": "OWASP WSTG-BUSL-02/04 ",
    },
    {
        "Control": "1.4 – Parameter Tampering",
        "References": "OWASP WSTG-INPV-02/04 ",
    },
    {
        "Control": "1.5 – Obfuscation & Hashing",
        "References": "OWASP WSTG-CRYP-01 ",
    },
    {
        "Control": "1.6 – Sensitive Data Exposure",
        "References": "OWASP WSTG-CRYP-04 ",
    },
    {
        "Control": "1.7 – Business Logic Abuse",
        "References": "OWASP WSTG-BUSL-01/07 ",
    },
]


def control_references():
    return tabulate(
        controls,
        headers="keys",
        tablefmt="fancy_grid",
        stralign="left",
        numalign="left",
    )
