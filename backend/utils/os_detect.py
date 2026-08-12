"""
Détecte la famille OS (linux / windows) à partir du texte os_info
renvoyé par Nmap (HostResult.os_info), pour choisir automatiquement
la bonne commande SSH — au lieu de laisser le LLM deviner via le
feedback de l'ingénieur.
"""


def detect_os_family(os_info: str | None) -> str:
    """
    Retourne "windows", "linux" ou "unknown" à partir du texte os_info
    (ex: "Microsoft Windows 10", "Linux 5.4 - 5.15", "Linux 3.X|4.X").
    """
    if not os_info:
        return "unknown"

    lowered = os_info.lower()

    if any(marker in lowered for marker in ("windows", "microsoft")):
        return "windows"

    if any(
        marker in lowered
        for marker in ("linux", "ubuntu", "debian", "centos", "unix", "fedora", "red hat")
    ):
        return "linux"

    return "unknown"