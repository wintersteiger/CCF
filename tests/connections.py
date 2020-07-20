# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.e2e_args
import time
import infra.network
import infra.proc
import ccf.checker
import contextlib
import resource
import psutil
import random

from loguru import logger as LOG


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 1)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        check = ccf.checker.Checker()
        network.start_and_join(args)
        primary, _ = network.find_nodes()

        primary_pid = primary.remote.remote.proc.pid
        num_fds = psutil.Process(primary_pid).num_fds()
        max_fds = num_fds + 50
        LOG.info(f"{primary_pid} has {num_fds} open file descriptors")

        resource.prlimit(primary_pid, resource.RLIMIT_NOFILE, (max_fds, max_fds))
        LOG.info(f"set max fds to {max_fds} on {primary_pid}")

        nb_conn = (max_fds - num_fds) * 2
        clients = []

        with contextlib.ExitStack() as es:
            for i in range(nb_conn):
                try:
                    clients.append(es.enter_context(primary.client("user0")))
                    LOG.info(f"Connected client {i}")
                except OSError:
                    LOG.error(f"Failed to connect client {i}")

            c = clients[int(random.random() * len(clients))]
            check(c.post("/app/log/private", {"id": 42, "msg": "foo"}), result=True)

            assert (
                len(clients) >= max_fds - num_fds - 1
            ), f"{len(clients)}, expected at least {max_fds - num_fds - 1}"

            num_fds = psutil.Process(primary_pid).num_fds()
            LOG.info(f"{primary_pid} has {num_fds} open file descriptors")
            LOG.info("Disconnecting clients")

        time.sleep(1)
        num_fds = psutil.Process(primary_pid).num_fds()
        LOG.info(f"{primary_pid} has {num_fds} open file descriptors")

        clients = []
        with contextlib.ExitStack() as es:
            for i in range(max_fds - num_fds):
                clients.append(es.enter_context(primary.client("user0")))
                LOG.info(f"Connected client {i}")

            c = clients[int(random.random() * len(clients))]
            check(c.post("/app/log/private", {"id": 42, "msg": "foo"}), result=True)

            assert (
                len(clients) >= max_fds - num_fds - 1
            ), f"{len(clients)}, expected at least {max_fds - num_fds - 1}"

            num_fds = psutil.Process(primary_pid).num_fds()
            LOG.info(f"{primary_pid} has {num_fds} open file descriptors")
            LOG.info("Disconnecting clients")

        time.sleep(1)
        num_fds = psutil.Process(primary_pid).num_fds()
        LOG.info(f"{primary_pid} has {num_fds} open file descriptors")


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., liblogging)",
            default="liblogging",
        )

    args = infra.e2e_args.cli_args(add)
    run(args)
