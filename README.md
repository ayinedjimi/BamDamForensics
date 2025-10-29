# 🚀 BamDamForensics


**WinToolsSuite Serie 3 - Forensics Tool #23**

## 📋 Description

BamDamForensics est un outil forensique spécialisé pour parser et analyser les données BAM (Background Activity Moderator) et DAM (Desktop Activity Moderator) de Windows 10/11. Ces services enregistrent les timestamps ultra-précis (avec millisecondes) de la dernière exécution de chaque application par utilisateur, offrant une timeline forensique de haute précision.


## ✨ Fonctionnalités

### Parsing BAM/DAM
- **BAM (Background Activity Moderator)** : Service Windows 10+ (1709+) qui enregistre l'activité d'arrière-plan
- **DAM (Desktop Activity Moderator)** : Variante pour Desktop Windows 10 (certaines éditions)
- **Précision** : Timestamps avec millisecondes (supérieur à ShimCache/Prefetch)
- **Couverture** : Tous les utilisateurs du système (via SIDs)

### Extraction de Données
- **Timestamp** : Date/heure de dernière exécution (format: JJ/MM/AAAA HH:MM:SS.mmm)
- **SID** : Security Identifier de l'utilisateur
- **Username** : Résolution automatique SID → nom d'utilisateur via `LookupAccountSid`
- **Executable Path** : Chemin complet de l'exécutable
- **Source** : BAM ou DAM
- **Notes** : Détection automatique de chemins suspects

### Détection Automatique
Marquage automatique des emplacements suspects :
- **\Temp\** : Répertoire temporaire
- **\Downloads\** : Téléchargements
- Autres patterns malveillants

### Interface Graphique
- **ListView 6 colonnes** :
  - **Timestamp** : Date/heure précise (millisecondes)
  - **SID** : Identifiant de sécurité
  - **Username** : Nom d'utilisateur résolu
  - **Chemin Exec** : Path complet de l'exécutable
  - **Source** : BAM ou DAM
  - **Notes** : Observations (suspect, etc.)

- **Boutons** :
  - **Parser BAM/DAM** : Extraction depuis le registre
  - **Trier par Date** : Tri chronologique (plus récent en premier)
  - **Filtrer par User** : Statistiques par utilisateur
  - **Exporter CSV** : Export complet UTF-8

### Export et Logging
- **Export CSV UTF-8** avec BOM
- **Colonnes** : Timestamp, SID, Username, CheminExec, Source, Notes
- **Logging automatique** : `BamDamForensics.log`


## Architecture Technique

### Clés Registry

#### BAM (Background Activity Moderator)
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}
```

#### DAM (Desktop Activity Moderator)
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\{SID}
```

**Important** : Nécessite droits administrateur.

### Structure de Données

Chaque sous-clé `{SID}` contient des valeurs :
- **Nom de valeur** : Chemin complet de l'exécutable (ex: `C:\Windows\System32\notepad.exe`)
- **Type** : REG_BINARY
- **Données** : FILETIME (8 bytes, format little-endian)

**FILETIME** : Nombre de intervals de 100 nanosecondes depuis le 1er janvier 1601 (UTC).

### Exemple

```
[HKLM\...\bam\State\UserSettings\S-1-5-21-...-1001]
  "C:\Windows\System32\cmd.exe" = REG_BINARY : 80 A6 F4 7C 6F 74 DA 01
  "C:\Program Files\...\chrome.exe" = REG_BINARY : 90 B7 05 8D 6F 74 DA 01
```

Conversion FILETIME → Date :
- `0x01DA74 6F7CF4A680` → 15/03/2024 14:23:45.123

### Algorithme de Parsing

1. **Énumération des SIDs**
   - Ouvrir `HKLM\...\bam\State\UserSettings`
   - Énumérer toutes les sous-clés (chaque sous-clé = un SID)

2. **Résolution SID → Username**
   - `ConvertStringSidToSidW` : Conversion string SID → PSID
   - `LookupAccountSidW` : Résolution PSID → Domain\Username

3. **Énumération des valeurs**
   - Pour chaque SID, énumérer toutes les valeurs
   - Filtrer la valeur "Version" (métadonnée non pertinente)

4. **Extraction FILETIME**
   - Lecture des 8 bytes de données binaires
   - Conversion en ULONGLONG (little-endian)
   - `FileTimeToSystemTime` → timestamp lisible

5. **Détection de suspicion**
   - Analyse du chemin de l'exécutable
   - Marquage si patterns suspects détectés

6. **Affichage dans ListView**
   - Population de toutes les colonnes
   - Formatage timestamp avec millisecondes

### Threading
- **Worker thread** pour parsing (opération I/O intensive)
- **UI thread** reste réactive
- **Message WM_USER + 1** pour signaler fin de parsing

### RAII
- **RegKey** : Wrapper RAII pour `HKEY`
  - Fermeture automatique via `RegCloseKey`


## 🚀 Utilisation

### Scénario 1 : Timeline Ultra-Précise

**Contexte** : Investigation nécessitant précision au niveau de la seconde/milliseconde

1. **Lancer l'outil en Administrateur**
   - Clic droit > "Exécuter en tant qu'administrateur"

2. **Cliquer "Parser BAM/DAM"**
   - Extraction automatique de tous les SIDs
   - Résolution des usernames

3. **Cliquer "Trier par Date"**
   - Tri chronologique (plus récent en premier)

4. **Analyser la timeline**
   - Précision millisecondes = corrélation précise avec logs réseau, Event Logs, etc.

**Exemple** :
```
15/03/2024 14:23:45.123 - DOMAIN\JohnDoe - C:\Windows\System32\cmd.exe
15/03/2024 14:23:45.456 - DOMAIN\JohnDoe - C:\Users\...\Downloads\tool.exe
15/03/2024 14:23:46.789 - DOMAIN\JohnDoe - C:\Windows\System32\net.exe
```
→ Séquence d'attaque en moins de 2 secondes

### Scénario 2 : Détection de Malware

**Indicateurs dans BAM/DAM** :
- Exécutables dans Downloads/, Temp/
- Exécutables avec noms suspects
- Timestamps inhabituels (heures non-ouvrées)

**Méthodologie** :
1. Parser BAM/DAM
2. Trier par date
3. Filtrer les entrées avec "Notes" = "Emplacement suspect"
4. Croiser avec antivirus, VirusTotal

### Scénario 3 : Analyse Multi-Utilisateurs

**Objectif** : Identifier quel utilisateur a exécuté quoi

1. **Parser BAM/DAM**

2. **Cliquer "Filtrer par User"**
   - Statistiques : nombre d'exécutions par utilisateur

3. **Analyser les patterns**
   - Utilisateurs avec activité anormale
   - Comptes de service exécutant des applications user

**Exemple de rapport** :
```
=== Statistiques par Utilisateur ===

DOMAIN\JohnDoe : 145 exécutions
DOMAIN\Administrator : 23 exécutions
SYSTEM : 89 exécutions
```

### Scénario 4 : Corrélation avec Autres Artefacts

**Timeline multi-sources** :
- **BAM/DAM** : Timestamp précis de dernière exécution
- **Prefetch** : Timestamps d'exécutions multiples + run count
- **UserAssist** : Run count + focus time
- **ShimCache** : Présence sur le système (exécuté ou non)

**Méthodologie** :
1. Extraire BAM/DAM (timestamps précis)
2. Extraire Prefetch (run count)
3. Extraire UserAssist (usage)
4. Fusionner dans une timeline unifiée

**Corrélation** :
- BAM dit "dernière exec = 15/03/2024 14:23:45"
- Prefetch dit "5 exécutions au total"
- UserAssist dit "focus time = 2 minutes"
→ Profil complet de l'activité

### Scénario 5 : Lateral Movement

**Détection** : Attaquant utilise PsExec pour mouvement latéral

**Indicateurs BAM/DAM** :
- `C:\Windows\psexesvc.exe` (service PsExec installé)
- Timestamp = moment de l'attaque
- Username = compte compromis

**Corrélation** :
- Event Logs : Connexion réseau au timestamp identique
- Network logs : Connexion SMB depuis IP attaquant
- BAM/DAM : Preuve d'exécution locale


## Avantages de BAM/DAM vs Autres Artefacts

### Avantages
1. **Précision** : Millisecondes (vs ShimCache = secondes, Prefetch = secondes)
2. **Multi-utilisateurs** : Tous les SIDs enregistrés (vs UserAssist = HKCU seulement)
3. **Persistance** : Survit aux redémarrages (vs processus en mémoire)
4. **Exhaustivité** : Tous les exécutables (vs Prefetch = seulement certains)
5. **Léger** : Pas de fichiers volumineux (vs Prefetch = fichiers .pf par exe)

### Limitations
1. **Windows 10+ seulement** : Pas de support XP/7/8 (BAM introduit en Win10 1709)
2. **Dernière exécution seulement** : Pas d'historique complet (vs Prefetch = last 8 run times)
3. **Pas de run count** : Pas de compteur d'exécutions (vs UserAssist/Prefetch)
4. **Peut être nettoyé** : Attaquant averti peut effacer (nécessite admin)

### Quand Utiliser BAM/DAM
- **Timeline précise** : Besoin de millisecondes
- **Multi-users** : Investigation sur plusieurs comptes
- **Windows 10+** : Systèmes modernes uniquement
- **Corrélation** : Complémentaire à Prefetch/UserAssist


## 🚀 Cas d'Usage Forensique

### 1. Ransomware Timeline
- **Problème** : Déterminer l'heure exacte d'exécution du ransomware
- **Solution** : BAM/DAM fournit timestamp précis de l'exe du ransomware
- **Exemple** : `C:\Users\...\Downloads\invoice.exe` = 15/03/2024 14:23:45.123

### 2. Insider Threat
- **Problème** : Employé suspecté de copie de données sensibles
- **Solution** : Timeline d'outils de compression/transfert
- **Exemples** :
  - `C:\Program Files\7-Zip\7z.exe` = 14:20:00
  - `C:\Program Files\FileZilla\filezilla.exe` = 14:25:00
→ Compression puis transfert FTP

### 3. Lateral Movement
- **Problème** : Détecter mouvement latéral via PsExec/WMI
- **Solution** : Recherche de `psexesvc.exe`, `WMIC.exe`, `powershell.exe`
- **Timeline** : Corrélation avec connexions réseau

### 4. Living off the Land
- **Problème** : Attaquant utilise outils Windows légitimes
- **Solution** : Détecter usage inhabituel de certutil, bitsadmin, etc.
- **Exemple** : `C:\Windows\System32\certutil.exe` à 3h du matin (suspect)

### 5. Malware Staging
- **Problème** : Malware télécharge puis exécute payload
- **Solution** : Timeline montrant téléchargement → exécution
- **Exemple** :
  - `C:\Windows\System32\bitsadmin.exe` = 14:20:00 (download)
  - `C:\Users\...\AppData\Local\Temp\payload.exe` = 14:20:05 (exec)


## Différences BAM vs DAM

### BAM (Background Activity Moderator)
- **Présent sur** : Windows 10 version 1709+ (toutes éditions)
- **Objectif** : Gérer l'activité d'arrière-plan des applications
- **Clé** : `HKLM\...\Services\bam\...`

### DAM (Desktop Activity Moderator)
- **Présent sur** : Windows 10 Desktop (certaines éditions)
- **Objectif** : Gérer l'activité des applications de bureau
- **Clé** : `HKLM\...\Services\dam\...`

### Quelle Clé Utiliser ?
- **Windows 10/11 Desktop** : Vérifier BAM et DAM
- **Windows Server** : BAM uniquement (généralement)
- **Recommandation** : Parser les deux systématiquement

### Contenu Identique
Les données sont généralement identiques entre BAM et DAM. Si les deux existent, préférer BAM (plus fiable).


## Évolutions Futures

### Fonctionnalités Planifiées
1. **Timeline graphique** :
   - Visualisation chronologique avec zoom
   - Heatmap d'activité par heure/jour

2. **Corrélation multi-sources** :
   - Fusion automatique avec Prefetch, UserAssist, ShimCache
   - Timeline unifiée

3. **Détection avancée** :
   - Machine learning pour détecter patterns anormaux
   - Baseline par utilisateur

4. **Export avancé** :
   - Format JSON pour SIEM
   - Format MACB (plaso) pour timeline forensique


## Compilation

### Prérequis
- Visual Studio 2019 ou supérieur
- Windows SDK 10.0 ou supérieur
- Architecture : x86 ou x64

### Build
```batch
go.bat
```

### Fichiers Générés
- `BamDamForensics.exe` (exécutable principal)
- `BamDamForensics.log` (log runtime)


## Permissions

**Important** : L'outil nécessite **droits administrateur** pour accéder aux clés HKLM.

### Lancer en Administrateur
1. Clic droit sur `BamDamForensics.exe`
2. "Exécuter en tant qu'administrateur"


## Références Techniques

### Documentation
- [BAM Forensics by Hexacorn](https://www.hexacorn.com/blog/2017/10/26/beyond-good-ol-run-key-part-73/)
- [BAM/DAM Analysis by SANS](https://www.sans.org/blog/bam-forensics/)
- [Windows 10 Forensics (Zimmerman)](https://www.13cubed.com/)

### Outils Similaires
- **RegRipper** : Plugin pour BAM/DAM
- **Registry Explorer** : GUI avec support BAM/DAM


## 🔧 Troubleshooting

### Problème : "Aucune donnée BAM/DAM trouvée"
- **Cause 1** : Windows < 10 version 1709 (BAM n'existe pas)
- **Cause 2** : Permissions insuffisantes
- **Solution** : Vérifier version Windows, exécuter en admin

### Problème : "Impossible d'ouvrir la clé"
- **Cause** : Pas de droits administrateur
- **Solution** : Clic droit > Exécuter en tant qu'administrateur

### Problème : "SID inconnu"
- **Cause** : Utilisateur supprimé du système
- **Solution** : Normal, le SID est affiché mais non résolvable


## 📄 Licence

MIT License - WinToolsSuite Project


## 👤 Auteur

WinToolsSuite Development Team


## 📝 Changelog

### Version 1.0 (2025)
- Version initiale
- Support Windows 10/11
- Parsing BAM et DAM
- Résolution automatique SID → Username
- Export CSV UTF-8
- Interface française
- Logging complet


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>