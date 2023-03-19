import click
from get_info import get_mx, get_reputation, get_url


def print_header():
    click.echo("#### Domain Check Tools ####")


def check_domain(domain, mx, reputation, url):
    click.echo(domain)
    if reputation:
        result = get_reputation(domain)
        click.echo(f'Reputation: {result}')
    if mx:
        result = get_mx(domain)
        click.echo(f'MX: {result}')
    if url:
        result = get_url(domain)
        click.echo(f'URL: {result}')
    click.echo()


@click.command()
@click.argument('domain', nargs=-1)
@click.option('--file', type=click.Path(exists=True), help='Input file containing domain list')
@click.option('-r', '--reputation', is_flag=True, help='Get reputation for domain')
@click.option('-m', '--mx', is_flag=True, help='Get MX record for domain')
@click.option('-u', '--url', is_flag=True, help='Get URL for domain')
def main(domain, file, reputation, mx, url):
    print_header()
    domain_list = []
    if file:
        with open(file, 'r') as f:
            domain_list = [line.strip() for line in f if line.strip()]
    if domain:
        domain_list.extend(domain)
    if not domain_list:
        click.echo(click.style('#### Please ENTER domain(s) ####', fg='red'))
        return
    for domain in domain_list:
        check_domain(domain, reputation, mx, url)


if __name__ == '__main__':
    main()
