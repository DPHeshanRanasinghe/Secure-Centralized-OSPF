"""
sc_ospf.py — SC-OSPF: Secure & Centralized OSPF (Proposed Protocol)
EN2150 Assignment 4

Improvements over standard OSPF:

  IMPROVEMENT 1 — Security (HMAC-SHA256 Authentication)
    Each router shares a secret key with the central controller.
    Every LSA is signed using HMAC-SHA256.
    The controller verifies the signature before accepting any LSA.
    A compromised router cannot forge another router's signature
    because it does not know the victim's secret key.
    Result: LSA injection attacks are detected and rejected.

  IMPROVEMENT 2 — Fast Convergence (Centralized Computation)
    Instead of wave-by-wave flooding, every router sends its LSA
    directly to the central controller in Round 1.
    The controller runs Dijkstra once for all routers in Round 2
    and pushes forwarding tables back to each router.
    Result: Always converges in exactly 2 rounds, regardless of
    network size or diameter.

Protocol Message Flow:
    Round 1: Router_i → Controller  (signed LSA)
    Round 2: Controller → Router_i  (forwarding table)

Security Mechanism:
    - Each router i has a pre-shared key K_i with the controller
    - LSA content: {router_id, neighbors, seq_num}
    - Signature:   HMAC-SHA256(K_i, LSA_content)
    - Controller verifies: HMAC-SHA256(K_i, LSA_content) == received_sig
    - Attacker does not know K_victim, so signature always fails
"""

import networkx as nx
import hmac
import hashlib
import json


# ──────────────────────────────────────────────
# SCOSPFController — the central control entity
# ──────────────────────────────────────────────

class SCOSPFController:
    """
    The SC-OSPF central controller.
    Equivalent to an SDN controller (as covered in Session 6).

    Responsibilities:
      1. Store a pre-shared secret key for every router
      2. Receive and cryptographically verify LSAs
      3. Build the complete verified topology graph
      4. Run Dijkstra centrally for all source routers
      5. Distribute forwarding tables back to each router
    """

    def __init__(self, graph):
        self.graph = graph

        # Verified topology database (only verified LSAs stored here)
        # Format: {router_id: {neighbor_id: cost}}
        self.verified_topology = {}

        # Final forwarding tables pushed to each router
        # Format: {router_id: {destination: (next_hop, cost)}}
        self.forwarding_tables = {}

        # Counters for reporting
        self.messages_received = 0
        self.lsas_accepted = 0
        self.lsas_rejected = 0

        # Pre-shared secret keys — one per router
        # In a real deployment, these are distributed during router provisioning
        # (similar to how 802.1X certificates are distributed)
        self.secret_keys = self._generate_secret_keys()

    def _generate_secret_keys(self):
        """
        Generate a unique 256-bit HMAC key for each router.
        In production, these would be provisioned securely during
        router installation (e.g., via a PKI system).
        """
        keys = {}
        for node in self.graph.nodes():
            # Key = HMAC-SHA256 of a unique seed per router
            seed = f"SC_OSPF_KEY_ROUTER_{node}_SECRET_2024".encode()
            keys[node] = hashlib.sha256(seed).digest()  # 32-byte key
        return keys

    def _compute_signature(self, router_id, lsa_payload):
        """
        Compute the HMAC-SHA256 signature for an LSA.

        Parameters:
            router_id   : ID of the router that owns this LSA
            lsa_payload : dict containing the LSA fields

        Returns:
            Hex-encoded HMAC-SHA256 signature string
        """
        key = self.secret_keys[router_id]
        # Serialize payload deterministically (sort_keys ensures consistent ordering)
        message = json.dumps(lsa_payload, sort_keys=True).encode('utf-8')
        signature = hmac.new(key, message, hashlib.sha256).hexdigest()
        return signature

    def verify_lsa(self, claimed_router_id, lsa_payload, received_signature):
        """
        Verify an incoming LSA's HMAC-SHA256 signature.

        The controller recomputes the expected signature using the
        secret key it shares with claimed_router_id.
        If the recomputed signature matches received_signature,
        the LSA is authentic. Otherwise it is rejected.

        Parameters:
            claimed_router_id  : router ID in the LSA header
            lsa_payload        : the LSA data fields
            received_signature : signature attached to the LSA

        Returns:
            True if authentic, False if tampered or forged
        """
        if claimed_router_id not in self.secret_keys:
            return False  # Unknown router — reject

        expected_signature = self._compute_signature(
            claimed_router_id, lsa_payload
        )

        # hmac.compare_digest prevents timing-based side-channel attacks
        return hmac.compare_digest(expected_signature, received_signature)

    def receive_lsa(self, claimed_router_id, lsa_payload, signature):
        """
        Entry point for incoming LSAs from routers.

        Verifies signature first. If valid, stores in verified_topology.
        If invalid (attack or corruption), drops the LSA and increments
        the rejection counter.

        Returns:
            True if accepted, False if rejected
        """
        self.messages_received += 1

        if self.verify_lsa(claimed_router_id, lsa_payload, signature):
            # Authentic LSA — store in verified topology
            self.verified_topology[claimed_router_id] = \
                lsa_payload['neighbors']
            self.lsas_accepted += 1
            return True
        else:
            # Forged or tampered LSA — silently drop
            self.lsas_rejected += 1
            return False

    def compute_and_distribute_routes(self):
        """
        Round 2 of SC-OSPF:
          1. Build a graph from the verified topology
          2. Run Dijkstra from every router's perspective
          3. Store forwarding tables for each router

        Returns:
            dict: {router_id: {destination: (next_hop, cost)}}
        """
        # Build NetworkX graph from verified, authenticated topology
        topo = nx.Graph()
        for r_id, neighbors in self.verified_topology.items():
            for nbr_id, cost in neighbors.items():
                # Use string-keyed integer conversion for safety
                topo.add_edge(int(r_id), int(nbr_id), cost=cost)

        self.forwarding_tables = {}

        for source in topo.nodes():
            try:
                path_lengths = nx.single_source_dijkstra_path_length(
                    topo, source, weight='cost'
                )
                path_routes = nx.single_source_dijkstra_path(
                    topo, source, weight='cost'
                )

                self.forwarding_tables[source] = {}
                for dest, cost in path_lengths.items():
                    if dest == source:
                        continue
                    path = path_routes[dest]
                    next_hop = path[1] if len(path) > 1 else dest
                    self.forwarding_tables[source][dest] = (next_hop, cost)

            except nx.NetworkXError:
                pass

        return self.forwarding_tables

    def get_forwarding_table(self, router_id):
        """Return the forwarding table for a specific router."""
        return self.forwarding_tables.get(router_id, {})


# ──────────────────────────────────────────────
# SCOSPFNetwork — the complete SC-OSPF system
# ──────────────────────────────────────────────

class SCOSPFNetwork:
    """
    Manages the complete SC-OSPF network.

    Key difference from standard OSPF:
      - Routers do NOT flood LSAs peer-to-peer
      - All LSAs go directly to the controller (1 hop always)
      - Controller verifies, computes, and distributes routes
      - Total convergence: exactly 2 rounds for any network size
    """

    def __init__(self, graph):
        self.graph = graph
        self.controller = SCOSPFController(graph)
        self.total_messages = 0

    def simulate_convergence(self):
        """
        Simulate SC-OSPF convergence.

        Round 1: Each router signs its LSA and sends to the controller.
        Round 2: Controller verifies all LSAs, runs Dijkstra, pushes
                 forwarding tables back to each router.

        Returns:
            Always 2 (fixed, independent of network size)
        """
        SEQ_NUM = 1

        # ── Round 1: Routers → Controller ──
        for router_id in self.graph.nodes():
            # Build this router's link state
            neighbors = {}
            for nbr in self.graph.neighbors(router_id):
                neighbors[nbr] = self.graph[router_id][nbr]['cost']

            lsa_payload = {
                'router_id': router_id,
                'neighbors': neighbors,
                'seq_num': SEQ_NUM
            }

            # Sign the LSA with this router's secret key
            signature = self.controller._compute_signature(
                router_id, lsa_payload
            )

            # Send signed LSA to controller (1 message per router)
            self.controller.receive_lsa(router_id, lsa_payload, signature)
            self.total_messages += 1

        # ── Round 2: Controller → Routers ──
        self.controller.compute_and_distribute_routes()
        # Controller sends one forwarding table per router
        self.total_messages += len(self.graph.nodes())

        return 2  # Always 2 rounds

    def simulate_lsa_injection_attack(self, attacker_id, victim_id,
                                      fake_cost=1):
        """
        Attempt an LSA injection attack against SC-OSPF.

        The attacker creates a fake LSA claiming to be the victim router
        and sends it to the controller. However, the attacker only knows
        its OWN secret key, not the victim's. The HMAC verification at
        the controller will fail because the signature was computed with
        the wrong key.

        Parameters:
            attacker_id : compromised router attempting the attack
            victim_id   : legitimate router being impersonated
            fake_cost   : the fake (low) link cost to attract traffic

        Returns:
            (0, 0) — SC-OSPF always blocks this attack
        """
        SEQ_NUM = 999  # High seq to try to override legitimate LSA

        # Build fake link state (attacker wants to attract all traffic)
        fake_neighbors = {}
        for node in self.graph.nodes():
            if node != victim_id:
                fake_neighbors[node] = fake_cost

        fake_lsa_payload = {
            'router_id': victim_id,    # Pretending to be victim
            'neighbors': fake_neighbors,
            'seq_num': SEQ_NUM
        }

        # Attacker signs with ITS OWN key (does not have victim's key)
        # This signature will NOT match what the controller expects
        # when it looks up victim_id's key
        attacker_key = self.controller.secret_keys[attacker_id]
        message = json.dumps(
            fake_lsa_payload, sort_keys=True
        ).encode('utf-8')
        forged_signature = hmac.new(
            attacker_key, message, hashlib.sha256
        ).hexdigest()

        # Controller receives and tries to verify with victim's key
        # → HMAC mismatch → rejected
        accepted = self.controller.receive_lsa(
            victim_id, fake_lsa_payload, forged_signature
        )

        # If rejected (as expected), routing tables remain unchanged
        # Return (corrupted_routers, changed_routes) = (0, 0)
        return (0, 0) if not accepted else (1, len(self.graph.nodes()))

    def get_forwarding_table(self, router_id):
        """Return forwarding table of a specific router."""
        return self.controller.get_forwarding_table(router_id)
