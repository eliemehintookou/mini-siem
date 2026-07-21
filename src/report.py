import json
from datetime import datetime

ORDRE_SEVERITE = {"CRITIQUE": 0, "HAUTE": 1, "MOYENNE": 2, "BASSE": 3, "INFO": 4}


def trier_alertes(alertes):
    return sorted(alertes, key=lambda a: ORDRE_SEVERITE.get(a.get("severite", "INFO"), 9))


def rapport_texte(alertes):
    lignes = []
    lignes.append("=" * 70)
    lignes.append("RAPPORT D'INCIDENTS - MINI SIEM")
    lignes.append(f"Genere le : {datetime.now().strftime('%d/%m/%Y a %H:%M:%S')}")
    lignes.append(f"Nombre d'alertes : {len(alertes)}")
    lignes.append("=" * 70)
  

    for i, a in enumerate(alertes, 1):
        lignes.append("")
        lignes.append(f"[{i}] {a.get('severite', 'INFO')} - {a.get('type', 'Inconnu')}")
        lignes.append(f"    Source        : {a.get('ip', '-')}")
        lignes.append(f"    Technique     : {a.get('mitre_technique', '-')} ({a.get('mitre_nom', '-')})")
        lignes.append(f"    Tactique      : {a.get('mitre_tactique', '-')}")
        lignes.append(f"    Description   : {a.get('description', '-')}")

    return lignes


def ecrire_rapport(alertes, chemin="reports/rapport.txt"):
    alertes = trier_alertes(alertes)
    lignes = rapport_texte(alertes)
    with open(chemin, "w") as f:
        f.write("\n".join(lignes))
    return "\n".join(lignes)


def ecrire_json(alertes, chemin="reports/alertes.json"):
    with open(chemin, "w") as f:
        json.dump(alertes, f, indent=2, default=str)


