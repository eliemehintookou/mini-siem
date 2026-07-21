MITRE = {
    "Brute Force SSH": {
        "technique": "T1110.001",
        "nom": "Brute Force: Password Guessing",
        "tactique": "Credential Access (TA0006)",
        "severite": "MOYENNE",
        "description": "Tentatives repetees de deviner un mot de passe valide.",
      },


"Connexion reussie apres brute force": {
        "technique": "T1078",
        "nom": "Valid Accounts",
        "tactique": "Initial Access / Persistence (TA0001, TA0003)",
        "severite": "CRITIQUE",
        "description": "Utilisation d'un compte legitime compromis pour acceder au systeme.",
    },
}

def enrichir(alerte):
    info = MITRE.get(alerte["type"])
    if info is None:
        alerte["mitre"] = "Non repertorie"
        alerte["severite"] = "INFO"
        return alerte

    alerte["mitre_technique"] = info["technique"]
    alerte["mitre_nom"] = info["nom"]
    alerte["mitre_tactique"] = info["tactique"]
    alerte["severite"] = info["severite"]
    alerte["description"] = info["description"]
    return alerte

if __name__ == "__main__":
    exemple = {"type": "Brute Force SSH", "ip": "203.0.113.66"}
    print(enrichir(exemple))

