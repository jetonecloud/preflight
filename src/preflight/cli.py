import typer

app = typer.Typer(
    name="preflight",
    help="Free, read-only AWS audit CLI. Finds the first three things to fix in deploys, cost, and bus factor.",
)


@app.command()
def demo() -> None:
    """Render a sample report with no AWS access required."""
    typer.echo("demo: not yet implemented")


@app.command()
def scan(
    profile: str = typer.Option(None, help="AWS profile to use."),
    region: str = typer.Option(None, help="AWS region to scan."),
    role_arn: str = typer.Option(None, help="IAM role to assume before scanning."),
) -> None:
    """Run a read-only audit against your AWS account."""
    typer.echo("scan: not yet implemented")


@app.command()
def preview() -> None:
    """Show exactly what would be sent if you opt in to email delivery."""
    typer.echo("preview: not yet implemented")


if __name__ == "__main__":
    app()
