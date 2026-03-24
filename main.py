import argparse
import threading
import time

from TOR_annuaire_v3 import annuaire_global
from TOR_serveur_v3 import Serveur
from TOR_client_v3 import Client


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6767
DEFAULT_SERVER_NAME = "ServeurEcho"
DEFAULT_ANNUAIRE_FILE = "annuaire.json"


def run_server(host: str, port: int, name: str, annuaire_out: str | None) -> None:
    server = Serveur(hote=host, port=port, nom=name)
    if annuaire_out:
        annuaire_global.sauvegarder(annuaire_out)
        print(f"[Main] Annuaire saved to: {annuaire_out}")
    server.demarrer()


def run_client(
    host: str,
    port: int,
    name: str,
    messages: list[str],
    annuaire_in: str | None,
) -> None:
    if annuaire_in:
        annuaire_global.charger(annuaire_in)
        print(f"[Main] Annuaire loaded from: {annuaire_in}")
    client = Client(hote=host, port=port, nom_serveur=name)
    for msg in messages:
        client.envoyer(msg)


def demo_mode(
    host: str,
    port: int,
    name: str,
    messages: list[str],
    show_annuaire: bool,
    annuaire_out: str | None,
) -> None:
    server = Serveur(hote=host, port=port, nom=name)
    server_thread = threading.Thread(target=server.demarrer, daemon=True)
    server_thread.start()

    time.sleep(0.3)

    if annuaire_out:
        annuaire_global.sauvegarder(annuaire_out)
        print(f"[Main] Annuaire saved to: {annuaire_out}")

    if show_annuaire:
        annuaire_global.lister()

    client = Client(hote=host, port=port, nom_serveur=name)
    for msg in messages:
        client.envoyer(msg)

    server_thread.join(timeout=2.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Launcher for the TOR demo (client/server).",
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--name", default=DEFAULT_SERVER_NAME)

    subparsers = parser.add_subparsers(dest="command", required=True)

    demo_parser = subparsers.add_parser("demo", help="Run server + client in one process")
    demo_parser.add_argument("messages", nargs="*")
    demo_parser.add_argument(
        "--show-annuaire",
        action="store_true",
        help="Display annuaire entries after server registration",
    )
    demo_parser.add_argument(
        "--annuaire-out",
        default=None,
        help="Save annuaire to JSON file (default: none)",
    )

    server_parser = subparsers.add_parser("server", help="Run server only")
    server_parser.add_argument("--note", action="store_true", help="Print a note about the local annuaire")
    server_parser.add_argument(
        "--annuaire-out",
        default=DEFAULT_ANNUAIRE_FILE,
        help="Save annuaire to JSON file",
    )

    client_parser = subparsers.add_parser("client", help="Run client only")
    client_parser.add_argument("messages", nargs="*")
    client_parser.add_argument(
        "--annuaire-in",
        default=DEFAULT_ANNUAIRE_FILE,
        help="Load annuaire from JSON file",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    default_messages = [
        "Hello server!",
        "RSA protects the AES session key.",
        "AES-GCM provides confidentiality and integrity.",
        "Tamper resistance is enforced by the GCM tag.",
        "QUIT",
    ]

    if args.command == "demo":
        messages = args.messages or default_messages
        print("\n=== TOR Demo ===")
        print(f"Host: {args.host}  Port: {args.port}  Server: {args.name}")
        demo_mode(
            args.host,
            args.port,
            args.name,
            messages,
            args.show_annuaire,
            args.annuaire_out,
        )
        return

    if args.command == "server":
        if args.note:
            print(
                "Note: annuaire_global is in-memory. "
                "Use 'demo' mode to run client+server in one process."
            )
        run_server(args.host, args.port, args.name, args.annuaire_out)
        return

    if args.command == "client":
        messages = args.messages or default_messages
        run_client(args.host, args.port, args.name, messages, args.annuaire_in)
        return


if __name__ == "__main__":
    main()
