from murpy.server import Server

__all__ = ['Server']


def main():
    from time import sleep
    from argparse import ArgumentParser

    argument_parser = ArgumentParser()
    argument_parser.add_argument('-c', '--certfile', required=True)
    argument_parser.add_argument('-k', '--keyfile', required=True)
    args = argument_parser.parse_args()
    server = Server(certfile=args.certfile, keyfile=args.keyfile)
    while server.is_alive():
        sleep(5)


if __name__ == '__main__':
    main()
