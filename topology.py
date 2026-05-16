"""
topology.py — Network topology generation for SC-OSPF simulation
"""

import networkx as nx
import random


def create_random_topology(num_nodes, seed=42):
    """
    Create a random connected network topology.
    Uses Watts-Strogatz small-world model (realistic for campus/internet).
    Each edge gets a link cost between 1 and 10.
    """
    random.seed(seed)

    # k=4 means each node starts connected to 4 neighbors
    # p=0.3 means 30% of edges rewired randomly (creates realistic topology)
    k = min(4, num_nodes - 1)
    G = nx.connected_watts_strogatz_graph(num_nodes, k=k, p=0.3, seed=seed)

    for u, v in G.edges():
        G[u][v]['cost'] = random.randint(1, 10)

    return G


def create_demo_topology():
    """
    Create a fixed 10-router topology used for the attack demonstration.
    This represents a small enterprise campus network.

    Topology:
        R0 --- R1 --- R3 --- R6
        |       |      |      |
        R2     R4     R7     R8
        |               |
        R5 ----------- R9
    """
    G = nx.Graph()

    # Define links: (router_a, router_b, link_cost)
    links = [
        (0, 1, 4),
        (0, 2, 3),
        (1, 3, 2),
        (1, 4, 5),
        (2, 5, 6),
        (3, 6, 3),
        (3, 7, 4),
        (4, 7, 2),
        (5, 9, 1),
        (6, 8, 4),
        (7, 9, 3),
        (8, 9, 2),
    ]

    for u, v, cost in links:
        G.add_edge(u, v, cost=cost)

    return G
