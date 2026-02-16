# SessionHunter

**SessionWatcher** est un outil Python permettant de surveiller en temps réel les sessions utilisateurs actives sur des machines Windows distantes. 

Il interroge le registre distant (`Remote Registry`) pour identifier les utilisateurs connectés et résout leurs SIDs en noms d'utilisateurs lisibles via LDAP ou SAMR.

## ⚡ Fonctionnalités

* **Temps réel** : Rafraîchit l'affichage toutes les 5 secondes (Dashboard).
* **Propre** : N'affiche que les machines ayant des sessions actives.
* **Sans Agent** : Aucune installation nécessaire sur la cible.
* **Résolution Hybride** :
    * **LDAP** : Résolution rapide via le Contrôleur de Domaine (nécessite `-dc-ip`).
    * **SAMR** : Résolution locale (fallback) pour les comptes locaux ou si LDAP échoue.
* **Scan de Domaine** : Peut scanner automatiquement toutes les machines de l'AD (`-dc-ip` sans cible).
* **Multi-threadé** : Rapide même sur un grand nombre de machines.

## 📋 Prérequis

* Python 3.x
* Un accès réseau aux machines cibles (Port 445/RPC).
* Le service **RemoteRegistry** doit être actif sur les cibles (activé par défaut sur Windows Server, souvent désactivé sur Windows 10/11 Workstations).
* Un compte utilisateur de domaine valide (pas besoin d'être Admin de Domaine, un utilisateur standard suffit si le RemoteRegistry est accessible).

## 🛠️ Installation

1. Clonez ce dépôt ou téléchargez le script.
2. Installez les dépendances :

```bash
pip3 install -r requirements.txt

```

*(Le fichier `requirements.txt` contient uniquement `impacket`)*.

## 🚀 Utilisation

### Syntaxe de base

```bash
python3 session-hunter.py [TARGET_IP] -u [USER] -p [PASSWORD] -d [DOMAIN]

```

### Exemples

#### 1. Surveiller une machine spécifique

```bash
python3 session-hunter.py 10.0.1.26 -u pavic -p 'Password1234!' -d INTRA.LOCAL

```

#### 2. Surveiller tout le domaine (Scan AD complet)

Si aucune cible n'est spécifiée mais que l'IP du DC est fournie, le script récupère toutes les machines de l'AD via LDAP et les surveille.

```bash
python3 session-hunter.py -u pavic -p 'Password1234!' -d INTRA.LOCAL -dc-ip 10.0.1.10

```

#### 3. Résolution optimisée avec LDAP (Recommandé)

Fournir l'IP du DC permet de résoudre les SIDs beaucoup plus efficacement. Vous pouvez aussi spécifier une base de recherche personnalisée (utile pour les domaines enfants ou les relations de confiance).

```bash
python3 session-hunter.py 10.0.1.26 -u pavic -p 'Password!' -d INTRA.LOCAL -dc-ip 10.0.1.10 -ldap-base "dc=lab,dc=local"

```

#### 4. Utilisation avec un Hash (Pass-the-Hash)

```bash
python3 session-hunter.py 10.0.1.26 -u pavic -H 'LMHASH:NTHASH' -d INTRA.LOCAL

```

## ⚙️ Arguments

| Argument | Description |
| --- | --- |
| `target` | (Optionnel) IP ou Nom d'hôte de la machine cible. Si omis, nécessite `-dc-ip`. |
| `-u`, `--username` | Nom d'utilisateur. |
| `-p`, `--password` | Mot de passe. |
| `-d`, `--domain` | Domaine Active Directory. |
| `-H`, `--hashes` | Authentification via Hash (Format `LM:NT`). |
| `-dc-ip` | Adresse IP du Contrôleur de Domaine (Requis pour le scan de masse et la résolution LDAP). |
| `-ldap-base` | (Optionnel) Base DN personnalisée pour la recherche LDAP (ex: `dc=sub,dc=domain,dc=com`). |
| `-t`, `--threads` | Nombre de threads pour le scan (Défaut: 10). |

## 🔎 Fonctionnement Technique

1. **Connexion** : Le script se connecte au pipe `winreg` (Windows Remote Registry) via SMB (Port 445).
2. **Énumération** : Il liste les sous-clés de la ruche `HKEY_USERS`. Chaque clé correspond au SID d'un utilisateur ayant une session (ou un profil chargé).
3. **Filtrage** : Il ignore les comptes systèmes (`S-1-5-18`, etc.) et les classes (`_Classes`).
4. **Résolution** :
* Il convertit le SID binaire et interroge le LDAP (si `-dc-ip` est fourni).
* Sinon, il interroge le service SAMR de la machine distante.


5. **Affichage** : Il affiche le résultat dans un tableau propre et recommence la boucle après 5 secondes.

## ⚠️ Dépannage

* **Rien ne s'affiche ?** : Le script n'affiche que les machines avec des sessions actives. Si personne n'est connecté, la liste reste vide.
* **"Unreachable / Service Stopped"** :
* Vérifiez que le pare-feu autorise le RPC/SMB (Port 445).
* Vérifiez que le service **RemoteRegistry** est démarré sur la cible.
* *Astuce :* Sur les versions clients (Win 10/11), ce service est souvent arrêté par défaut. Sur les serveurs, il est souvent actif.
