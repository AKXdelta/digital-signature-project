"""
app.py — Interface en ligne de commande (CLI)
Projet : Signature numérique de documents
Personne 4 : CLI + Intégration

Usage :
    python app.py generate-keys --algo rsa --out keys/ma_cle
    python app.py sign contrat.pdf --key keys/ma_cle_private.pem
    python app.py verify contrat.pdf --sig contrat.pdf.sig --key keys/ma_cle_public.pem
    python app.py audit contrat.pdf
"""

import sys
import click

# ─────────────────────────────────────────────
#  Groupe principal
# ─────────────────────────────────────────────

@click.group()
@click.version_option(version="1.0.0", prog_name="signdoc")
def cli():
    """
    SigDoc — Outil de signature numérique de documents.

    Supporte les formats PDF, JSON et TXT.
    Algorithmes disponibles : RSA-PSS 2048 bits et ECDSA P-256.
    """
    pass


# ─────────────────────────────────────────────
#  Commande 1 : generate-keys  (Personne 1)
# ─────────────────────────────────────────────

@cli.command("generate-keys")
@click.option(
    "--algo", "-a",
    default="rsa",
    type=click.Choice(["rsa", "ecdsa"], case_sensitive=False),
    show_default=True,
    help="Algorithme de signature (rsa ou ecdsa).",
)
@click.option(
    "--out", "-o",
    default="keys/ma_cle",
    show_default=True,
    help="Préfixe des fichiers de sortie (sans extension).",
)
def generate_keys(algo, out):
    """Génère une paire de clés cryptographiques (privée + publique)."""
    try:
        from crypto.keys import generate_keys as _generate
        _generate(algo=algo.lower(), prefix=out)
        click.secho(f"  Clé privée  : {out}_private.pem", fg="green")
        click.secho(f"  Clé publique: {out}_public.pem",  fg="green")
        click.secho(f"\n  Algorithme  : {algo.upper()}", fg="cyan")
    except ImportError:
        _module_missing("crypto.keys")
    except Exception as e:
        _error(f"Génération des clés échouée : {e}")


# ─────────────────────────────────────────────
#  Commande 2 : sign  (Personne 1 + 2 + 3)
# ─────────────────────────────────────────────

@cli.command("sign")
@click.argument("fichier", type=click.Path(exists=True))
@click.option(
    "--key", "-k",
    required=True,
    type=click.Path(exists=True),
    help="Chemin vers la clé privée (.pem).",
)
@click.option(
    "--algo", "-a",
    default="rsa",
    type=click.Choice(["rsa", "ecdsa"], case_sensitive=False),
    show_default=True,
    help="Algorithme utilisé pour la signature.",
)
@click.option(
    "--tsa/--no-tsa",
    default=True,
    show_default=True,
    help="Ajouter un horodatage TSA (RFC 3161).",
)
def sign(fichier, key, algo, tsa):
    """Signe un document (PDF, JSON ou TXT) et produit un fichier .sig."""
    try:
        from formats.dispatcher import sign_file
        from security.audit import log_action

        click.echo(f"\n  Signature de : {fichier}")
        sig_path = sign_file(fichier, key, algo=algo.lower())

        # Horodatage TSA optionnel (Personne 3)
        timestamp_token = None
        if tsa:
            try:
                from security.tsa import get_timestamp
                timestamp_token = get_timestamp(sig_path)
                click.secho("  Timestamp TSA : OK", fg="cyan")
            except Exception:
                click.secho("  Timestamp TSA : indisponible (continue sans)", fg="yellow")

        # Enregistrement dans l'audit trail
        log_action(
            action="sign",
            fichier=fichier,
            algo=algo.upper(),
            sig_path=sig_path,
            tsa_token=timestamp_token,
        )

        click.secho(f"\n  Signature créée : {sig_path}", fg="green")

    except ImportError as e:
        _module_missing(str(e))
    except FileNotFoundError as e:
        _error(f"Fichier introuvable : {e}")
    except Exception as e:
        _error(f"Signature échouée : {e}")


# ─────────────────────────────────────────────
#  Commande 3 : verify  (Personne 1 + 3)
# ─────────────────────────────────────────────

@cli.command("verify")
@click.argument("fichier", type=click.Path(exists=True))
@click.option(
    "--sig", "-s",
    required=True,
    type=click.Path(exists=True),
    help="Fichier de signature (.sig).",
)
@click.option(
    "--key", "-k",
    required=True,
    type=click.Path(exists=True),
    help="Chemin vers la clé publique (.pem).",
)
def verify(fichier, sig, key):
    """Vérifie la signature d'un document et affiche un rapport détaillé."""
    try:
        from crypto.verify import verify_file
        from security.audit import log_action

        click.echo(f"\n  Vérification de : {fichier}")
        result = verify_file(fichier, sig, key)

        # Affichage du rapport
        status  = result.get("status", "INCONNU")
        valid   = result.get("valid", False)
        expired = result.get("expired", False)

        if valid and not expired:
            click.secho(f"\n  Résultat : {status}", fg="green", bold=True)
        elif expired:
            click.secho(f"\n  Résultat : {status}", fg="yellow", bold=True)
        else:
            click.secho(f"\n  Résultat : {status}", fg="red", bold=True)

        # Détails complémentaires
        if "algo" in result:
            click.echo(f"  Algorithme  : {result['algo']}")
        if "signed_at" in result:
            click.echo(f"  Signé le    : {result['signed_at']}")
        if "signer" in result:
            click.echo(f"  Signataire  : {result['signer']}")

        # Enregistrement dans l'audit trail
        log_action(action="verify", fichier=fichier, status=status)

    except ImportError as e:
        _module_missing(str(e))
    except FileNotFoundError as e:
        _error(f"Fichier introuvable : {e}")
    except Exception as e:
        _error(f"Vérification échouée : {e}")


# ─────────────────────────────────────────────
#  Commande 4 : audit  (Personne 3)
# ─────────────────────────────────────────────

@cli.command("audit")
@click.argument("fichier", type=click.Path(exists=True))
@click.option(
    "--all", "show_all",
    is_flag=True,
    default=False,
    help="Afficher toutes les entrées sans limite.",
)
def audit(fichier, show_all):
    """Affiche l'historique complet des opérations sur un document."""
    try:
        from security.audit import show_audit
        click.echo(f"\n  Audit trail pour : {fichier}\n")
        show_audit(fichier, show_all=show_all)
    except ImportError as e:
        _module_missing(str(e))
    except FileNotFoundError:
        click.secho("  Aucun historique trouvé pour ce fichier.", fg="yellow")
    except Exception as e:
        _error(f"Lecture de l'audit trail échouée : {e}")


# ─────────────────────────────────────────────
#  Helpers internes (affichage d'erreurs)
# ─────────────────────────────────────────────

def _error(message: str) -> None:
    """Affiche une erreur en rouge et quitte proprement."""
    click.secho(f"\n  Erreur : {message}", fg="red", err=True)
    sys.exit(1)


def _module_missing(module: str) -> None:
    """Indique qu'un module d'un coéquipier n'est pas encore disponible."""
    click.secho(
        f"\n  Module manquant : {module}\n"
        f"  Assure-toi que le module est bien créé par ton coéquipier.",
        fg="yellow",
        err=True,
    )
    sys.exit(1)


# ─────────────────────────────────────────────
#  Point d'entrée
# ─────────────────────────────────────────────

if __name__ == "__main__":
    cli()
