"""
ospf.py — Standard OSPF Protocol Simulation
EN2150 Assignment 4 — SC-OSPF Protocol

Simulates:
  - LSA flooding across the network
  - Dijkstra route computation at each router
  - LSA injection attack (no authentication)

OSPF Weakness 1 (Security):
    LSAs are not authenticated. Any router can send a fake LSA
    claiming to be another router. All other routers accept it
    and corrupt their routing tables.

OSPF Weakness 2 (Convergence):
    Flooding is wave-based. Each router forwards to neighbors,
    who forward to their neighbors, and so on. Convergence takes
    as many rounds as the network diameter (longest shortest path).
    This grows with network size.
"""

import networkx as nx
from collections import defaultdict


# ──────────────────────────────────────────────
# Router class — one per node in the network
# ──────────────────────────────────────────────

class OSPFRouter:
    def __init__(self, router_id, graph):
        self.router_id = router_id
        self.graph = graph

        # Link State Database: stores link info advertised by each router
        # Format: {advertising_router_id: {neighbor_id: link_cost}}
        self.lsdb = {}

        # Routing table built by running Dijkstra on the LSDB
        # Format: {destination: (next_hop, total_cost)}
        self.routing_table = {}

        # Track which (source_router, seq_num) LSAs have been processed
        # to prevent duplicate processing during flooding
        self.seen_lsas = set()

        # Populate own LSA into LSDB immediately
        self._init_own_lsa()

    def _init_own_lsa(self):
        """Load own directly connected links into the LSDB."""
        my_links = {}
        for neighbor in self.graph.neighbors(self.router_id):
            my_links[neighbor] = self.graph[self.router_id][neighbor]['cost']
        self.lsdb[self.router_id] = my_links

    def receive_lsa(self, source_id, link_state, seq_num):
        """
        Receive an LSA packet.
        Returns True if this is a new LSA that should be forwarded.
        Returns False if already seen (suppress duplicate flooding).

        Parameters:
            source_id  : the router that originally generated this LSA
            link_state : dict {neighbor_id: cost} from that router's view
            seq_num    : sequence number to detect duplicates
        """
        lsa_key = (source_id, seq_num)

        if lsa_key in self.seen_lsas:
            return False  # Already processed, do not forward again

        # Mark as seen and update LSDB
        self.seen_lsas.add(lsa_key)
        self.lsdb[source_id] = link_state
        return True

    def compute_routes(self):
        """
        Run Dijkstra's algorithm on the current LSDB.
        Builds this router's routing table.
        """
        # Reconstruct graph from LSDB entries
        local_graph = nx.Graph()
        for router_id, neighbors in self.lsdb.items():
            for neighbor_id, cost in neighbors.items():
                local_graph.add_edge(router_id, neighbor_id, cost=cost)

        if self.router_id not in local_graph:
            return

        # Compute shortest paths from this router to all others
        try:
            path_lengths = nx.single_source_dijkstra_path_length(
                local_graph, self.router_id, weight='cost'
            )
            path_routes = nx.single_source_dijkstra_path(
                local_graph, self.router_id, weight='cost'
            )

            self.routing_table = {}
            for dest, total_cost in path_lengths.items():
                if dest == self.router_id:
                    continue
                path = path_routes[dest]
                # Next hop is the first router after self on the path
                next_hop = path[1] if len(path) > 1 else dest
                self.routing_table[dest] = (next_hop, total_cost)

        except nx.NetworkXError:
            pass


# ──────────────────────────────────────────────
# OSPFNetwork — manages all routers + simulation
# ──────────────────────────────────────────────

class OSPFNetwork:
    def __init__(self, graph):
        self.graph = graph
        self.routers = {
            node: OSPFRouter(node, graph)
            for node in graph.nodes()
        }
        self.convergence_rounds = 0
        self.total_messages = 0

    def simulate_convergence(self):
        """
        Simulate OSPF LSA flooding from scratch.

        Process:
          Round 0: Each router sends its own LSA to direct neighbors.
          Round N: Each recipient forwards new LSAs to its own neighbors.
          Done when no new LSAs are forwarded anywhere.

        Returns:
            Number of flooding rounds until full convergence.
        """
        SEQ_NUM = 1

        # Build the initial flood: each router sends its own LSA
        # Each entry is (destination_router_id, source_router_id, link_state, seq_num)
        current_wave = []

        for router_id, router in self.routers.items():
            # Gather this router's directly connected links
            my_links = {}
            for neighbor in self.graph.neighbors(router_id):
                my_links[neighbor] = self.graph[router_id][neighbor]['cost']

            # Send to all direct neighbors
            for neighbor in self.graph.neighbors(router_id):
                current_wave.append((neighbor, router_id, my_links, SEQ_NUM))
                self.total_messages += 1

        rounds = 0

        # Flood wave by wave until nothing left to propagate
        while current_wave:
            rounds += 1
            next_wave = []

            for (dest_id, src_id, link_state, seq_num) in current_wave:
                dest_router = self.routers[dest_id]
                is_new = dest_router.receive_lsa(src_id, link_state, seq_num)

                if is_new:
                    # Forward to all neighbors except where this came from
                    for neighbor in self.graph.neighbors(dest_id):
                        if neighbor != src_id:
                            next_wave.append(
                                (neighbor, src_id, link_state, seq_num)
                            )
                            self.total_messages += 1

            current_wave = next_wave

        # All routers now compute their routing tables from the LSDB
        for router in self.routers.values():
            router.compute_routes()

        self.convergence_rounds = rounds
        return rounds

    def simulate_lsa_injection_attack(self, attacker_id, victim_id,
                                      fake_cost=1):
        """
        Simulate an LSA injection attack.

        The attacker sends a fake LSA claiming to be the victim router,
        advertising false (very low) costs to attract all traffic.
        Because standard OSPF has no authentication, other routers
        accept the fake LSA without verification.

        Parameters:
            attacker_id : compromised router sending the fake LSA
            victim_id   : legitimate router being impersonated
            fake_cost   : artificially low link cost to attract traffic

        Returns:
            (corrupted_count, changed_routes_count)
        """
        ATTACK_SEQ = 999  # High sequence number overrides legitimate LSA

        # Build fake link-state: victim claims to connect to everyone cheaply
        fake_link_state = {}
        for node in self.graph.nodes():
            if node != victim_id:
                fake_link_state[node] = fake_cost  # Attract all traffic

        # Record routing tables before attack for comparison
        before_tables = {
            r_id: dict(r.routing_table)
            for r_id, r in self.routers.items()
        }

        # --- Inject the fake LSA ---
        # The attacker sends it out all its interfaces
        # Neighbors have no way to verify (no authentication in OSPF)
        propagation_queue = []
        for neighbor in self.graph.neighbors(attacker_id):
            propagation_queue.append(
                (neighbor, victim_id, fake_link_state, ATTACK_SEQ)
            )

        # Force acceptance: OSPF cannot detect the fake
        corrupted_ids = set()
        while propagation_queue:
            next_q = []
            for (dest_id, src_id, link_state, seq_num) in propagation_queue:
                router = self.routers[dest_id]
                # Remove from seen set so high seq_num forces acceptance
                router.seen_lsas.discard((src_id, seq_num))
                if router.receive_lsa(src_id, link_state, seq_num):
                    router.compute_routes()  # Re-routes based on fake data
                    corrupted_ids.add(dest_id)
                    for nbr in self.graph.neighbors(dest_id):
                        if nbr != src_id and nbr not in corrupted_ids:
                            next_q.append(
                                (nbr, src_id, link_state, seq_num)
                            )
            propagation_queue = next_q

        # Count how many routing entries changed across all routers
        total_changed = 0
        for r_id, router in self.routers.items():
            after = router.routing_table
            before = before_tables[r_id]
            for dest in before:
                if before.get(dest) != after.get(dest):
                    total_changed += 1

        return len(corrupted_ids), total_changed

    def get_routing_table(self, router_id):
        """Return routing table of a specific router."""
        return self.routers[router_id].routing_table

    def lsdb_complete(self):
        """Return True if all routers have full LSDB (all N routers)."""
        n = len(self.graph.nodes())
        return all(len(r.lsdb) == n for r in self.routers.values())
