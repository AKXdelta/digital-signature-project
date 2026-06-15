# 🔐 SigDoc — Signature Numérique de Documents

> Outil en ligne de commande pour la signature cryptographique de documents PDF, JSON et TXT — avec vérification d'intégrité, audit trail et horodatage TSA.

---

## 📋 Table des matières

- [Aperçu](#-aperçu)
- [Fonctionnalités](#-fonctionnalités)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Utilisation](#-utilisation)
- [Scénario de démonstration](#-scénario-de-démonstration--détection-de-fraude)
- [Dépannage](#-dépannage)

---

## 🧭 Aperçu

**SigDoc** implémente un pipeline complet de signature numérique de documents :

1. **Génération** d'une paire de clés cryptographiques (RSA-PSS 2048 bits ou ECDSA P-256)
2. **Signature** d'un document — calcul de l'empreinte SHA-256, chiffrement avec la clé privée
3. **Vérification** — contrôle d'intégrité et authenticité via la clé publique
4. **Audit Trail** — journal horodaté et chaîné par hachage de toutes les opérations

---

## ✨ Fonctionnalités

| Fonctionnalité | Détail |
|---|---|
| 🔑 Génération de clés | RSA-PSS 2048 bits et ECDSA P-256 |
| ✍️ Signature multi-formats | PDF, JSON, TXT |
| 🔍 Vérification | Rapport détaillé : `VALID` / `INVALID` |
| 🕐 Horodatage TSA | Conforme RFC 3161 via freetsa.org |
| 📋 Audit Trail | Journal chaîné par SHA-256, stocké en JSONL |
| 🖥️ Interface CLI | Commandes intuitives via Click |

---

## 🗂️ Architecture

```
digital-signature-project/
│
├── app.py                  # Point d'entrée CLI (Click)
├── requirements.txt        # Dépendances Python
│
├── crypto/                 # Moteur cryptographique
│   ├── hash.py             # Hachage SHA-256 / SHA-3
│   ├── keys.py             # Génération & chargement des clés PEM
│   ├── sign.py             # Signature RSA-PSS / ECDSA
│   ├── verify.py           # Vérification de signatures
│   └── tests/              # Fichiers de test (test.txt, test.json, test.pdf)
│
├── formats/                # Gestion des formats de documents
│   ├── dispatcher.py       # Routeur automatique selon l'extension
│   ├── txt_handler.py      # Traitement fichiers TXT
│   ├── json_handler.py     # Traitement fichiers JSON
│   └── pdf_handler.py      # Traitement fichiers PDF (PyPDF2)
│
├── security/               # Traçabilité et horodatage
│   ├── audit.py            # Audit trail chaîné par hachage
│   └── tsa.py              # Timestamps RFC 3161 (freetsa.org)
│
├── keys/                   # Clés générées — ignoré par Git (.gitignore)
├── signatures/             # Fichiers .sig générés
└── logs/                   # Journal d'audit (audit.jsonl)
```

---

## ⚙️ Installation

### Prérequis

- Python 3.10 ou supérieur
- pip

### Cloner le dépôt

```bash
git clone https://github.com/AKXdelta/digital-signature-project.git
cd digital-signature-project
```

### Installer les dépendances

```bash
pip install -r requirements.txt
```

> **Ubuntu / Debian avec Python 3.12+ :** si pip refuse, ajoute `--break-system-packages` :
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

### Vérifier l'installation

```bash
python app.py --help
```

---

## 🖥️ Utilisation

### 1. Générer une paire de clés

```bash
python app.py generate-keys --algo rsa --out keys/rsa
```

Crée deux fichiers dans `keys/` :
- `rsa_private.pem` — clé secrète de signature
- `rsa_public.pem` — clé publique de vérification

> Algorithmes disponibles : `rsa` (RSA-PSS 2048 bits) ou `ecdsa` (ECDSA P-256)

---

### 2. Signer un document

```bash
# Fichier TXT
python app.py sign crypto/tests/test.txt --key keys/rsa_private.pem --no-tsa

# Fichier JSON
python app.py sign crypto/tests/test.json --key keys/rsa_private.pem --no-tsa

# Fichier PDF
python app.py sign crypto/tests/test.pdf --key keys/rsa_private.pem --no-tsa
```

La signature est sauvegardée dans `signatures/<nom_fichier>.sig`.

> Supprimer `--no-tsa` pour activer l'horodatage RFC 3161 via freetsa.org.

---

### 3. Vérifier une signature

```bash
python app.py verify crypto/tests/test.txt \
  --sig signatures/test.txt.sig \
  --key keys/rsa_public.pem
```

Résultat attendu :
```
  Vérification de : crypto/tests/test.txt
✅ Signature VALID
  Résultat : VALID
  Algorithme  : RSA-PSS
```

---

### 4. Consulter l'audit trail

```bash
python app.py audit crypto/tests/test.txt
```

Affiche l'historique horodaté de toutes les opérations (signature, vérification) effectuées sur ce document.

---

### Aide intégrée

```bash
python app.py --help
python app.py sign --help
python app.py verify --help
```

---

## 🧪 Scénario de démonstration — Détection de fraude

Ce scénario illustre la capacité du système à détecter une altération malveillante d'un document.

### Étape A — Initialisation et signature intègre

```bash
echo "Message confidentiel original et intègre." > crypto/tests/test.txt
python app.py sign crypto/tests/test.txt --key keys/rsa_private.pem --no-tsa
```

### Étape B — Simulation d'une attaque (injection de données)

```bash
echo "ALERTE : Injection de données malveillantes par un attaquant." > crypto/tests/test.txt
```

### Étape C — Contrôle de sécurité

```bash
python app.py verify crypto/tests/test.txt \
  --sig signatures/test.txt.sig \
  --key keys/rsa_public.pem
```

Résultat attendu :
```
  Vérification de : crypto/tests/test.txt
❌ Signature INVALID
  Résultat : INVALID
  Algorithme  : RSA-PSS
```

> Le système calcule la divergence de l'empreinte SHA-256 et rejette explicitement le document altéré. La signature originale ne correspond plus au contenu modifié — la fraude est détectée.

---

## 🔧 Dépannage

### ❌ `Invalid signature at line 1` ou `CORROMPU` lors de la commande `audit`

**Cause :** Une nouvelle paire de clés a été générée alors que le journal d'audit contient des entrées signées avec les anciennes clés. Le système détecte la divergence mathématique et lève une exception de sécurité.

**Correction :** Purger le journal d'audit pour réinitialiser la chaîne de confiance :

```bash
> $(python3 -c "from security.audit import LOG_FILE; print(LOG_FILE)")
```

---

### ❌ `Error reading PDF: EOF marker not found`

**Cause :** Le fichier PDF de test a été écrasé par une commande `echo`, corrompant sa structure binaire (le marqueur `%%EOF` est absent).

**Correction :** Restaurer un fichier PDF minimal valide :

```bash
echo -e "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000062 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n115\n%%EOF" > crypto/tests/test.pdf
```

---

### ❌ `No module named 'PyPDF2'`

```bash
pip install PyPDF2 --break-system-packages
```

---

---

## 📄 Licence

Ce projet est distribué sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.
