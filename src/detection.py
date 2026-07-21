from collections import defaultdict
from datetime import datetime, timedelta

SEUIL_ECHECS = 5
FENETRE_MINUTES = 5





def convertir_date(texte):
     return datetime.strptime(f"2026 {texte}", "%Y %b %d %H:%M:%S")


def detecter_brute_force(evenements):
    alertes = []
    echecs_par_ip = defaultdict(list)

    for e in evenements:
        if not e["succes"]:
             echecs_par_ip[e["ip"]].append(convertir_date(e["date"]))

    for ip, dates in echecs_par_ip.items():
        dates.sort()
        meilleur = []
        for i in range(len(dates)):
            fin = dates[i]
            debut = fin - timedelta(minutes=FENETRE_MINUTES)
            dans_fenetre = [d for d in dates if debut <= d <= fin]
            if len(dans_fenetre) > len(meilleur):
                meilleur = dans_fenetre

        if len(meilleur) >= SEUIL_ECHECS:
                alertes.append({
                    "type": "Brute Force SSH",
                    "ip": ip,
                    "nombre_echecs": len(meilleur),
                    "debut": min(meilleur),
                    "fin": max(meilleur),
                })


    return alertes
def detecter_succes_apres_echecs(evenements, alertes_bf):
    alertes = []
    ips_suspectes = {a["ip"] for a in alertes_bf}

    for e in evenements:
        if e["succes"] and e["ip"] in ips_suspectes:
            alertes.append({
                "type": "Connexion reussie apres brute force",
                "ip": e["ip"],
                "utilisateur": e["utilisateur"],
                "date": convertir_date(e["date"]),
            })
    return alertes

if __name__ == "__main__":
    import sys
    sys.path.append("src")
    from parser import analyser_fichier
    from mitre import enrichir

    evenements = analyser_fichier("logs/auth.log")
    alertes = detecter_brute_force(evenements)
    alertes += detecter_succes_apres_echecs(evenements, alertes)
    alertes = [enrichir(a) for a in alertes]

    print(f"{len(alertes)} alerte(s) detectee(s)")
    for a in alertes:
        print(a)

