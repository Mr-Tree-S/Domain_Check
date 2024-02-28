import threading
import click
import time
from get_info import get_domain_info


def print_header():
    click.echo("#### Domain Check Tools ####")


# Multithreading Domain Check Process
def check_domain(domain_list, mx, reputation, urlscan):
    threads = []
    result_dict = {}
    for domain in domain_list:
        thread = threading.Thread(target=get_domain_info, args=(domain, mx, reputation, urlscan, result_dict))
        threads.append(thread)
        thread.start()
    
    # wait for all the threads to finish
    for thread in threads:
        thread.join()

    # print results in order
    for domain in domain_list:
        click.echo(f"Domain: {domain}")
        results = result_dict.get(domain, {})
        if 'reputation' in results:
            click.echo(f"Reputation: {results['reputation']}")
        if 'mx' in results:
            click.echo(f"MX: {results['mx']}")
        if 'urlscan' in results:
            click.echo(f"URL: {results['urlscan']}")
        click.echo()


@click.command()
@click.argument('domains', nargs=-1)
@click.option('--file', type=click.Path(exists=True), help='Input file containing domain list')
@click.option('-r', '--reputation', is_flag=True, help='Get Reputation for domain')
@click.option('-m', '--mx', is_flag=True, help='Get MX record for domain')
@click.option('-u', '--urlscan', is_flag=True, help='Get URL for domain')
@click.option('-t', '--threads', type=int, default=4, help='Number of threads to use for checking domains')
def main(domains, file, reputation, mx, urlscan, threads):
    start_time = time.time()    # Record the time started
    print_header()
    domain_list = []
    if file:
        with open(file, 'r') as f:
            domain_list = [line.strip() for line in f if line.strip()]
    if domains:
        domain_list.extend(domains)
    if not domain_list:
        click.echo(click.style('#### Please ENTER domain(s) ####', fg='red'))
        return

    # Split the task to each thread for processing
    num_threads = threads
    domain_lists = [domain_list[i:i+num_threads] for i in range(0, len(domain_list), num_threads)]
    for sub_domain_list in domain_lists:
        check_domain(sub_domain_list, mx, reputation, urlscan)

    end_time = time.time()  # Record the time end
    total_time = end_time - start_time  # Total running time
    click.echo(f"Total running time: {total_time:.2f} seconds")


if __name__ == '__main__':
    main()
