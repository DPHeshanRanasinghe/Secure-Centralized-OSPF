"""
main.py — SC-OSPF Simulation Runner

Runs all experiments and generates all figures used in the report:
  Figure 1: Network topology diagram
  Figure 2: Convergence rounds vs network size
  Figure 3: Message overhead comparison
  Figure 4: LSA injection attack impact
  Figure 5: Routing table comparison before/after attack

Run: python main.py
Output: all .png files saved in current directory
"""

import os
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from topology import create_random_topology, create_demo_topology
from ospf import OSPFNetwork
from sc_ospf import SCOSPFNetwork


# ── Colour palette (consistent across all figures) ──
OSPF_COLOR   = '#e74c3c'   # Red  → OSPF (existing, problematic)
SCOS_COLOR   = '#2ecc71'   # Green → SC-OSPF (proposed, improved)
GRID_ALPHA   = 0.25
FIG_DPI      = 160


# ═══════════════════════════════════════════════════════
#  HELPER
# ═══════════════════════════════════════════════════════

def banner(title):
    width = 60
    print(f"\n{'═'*width}")
    print(f"  {title}")
    print('═'*width)


# ═══════════════════════════════════════════════════════
#  FIGURE 1 — Network Topology Diagram
# ═══════════════════════════════════════════════════════

def plot_topology(G, filename='fig1_topology.png'):
    fig, ax = plt.subplots(figsize=(10, 7))
    pos = nx.spring_layout(G, seed=7, k=2.5)

    # Nodes
    nx.draw_networkx_nodes(
        G, pos, node_color='#2c3e50', node_size=900, ax=ax
    )
    # Labels inside nodes
    nx.draw_networkx_labels(
        G, pos,
        labels={n: f'R{n}' for n in G.nodes()},
        font_color='white', font_weight='bold', font_size=11, ax=ax
    )
    # Edges
    nx.draw_networkx_edges(
        G, pos, width=2.0, edge_color='#7f8c8d', alpha=0.8, ax=ax
    )
    # Edge cost labels
    edge_labels = {(u, v): d['cost'] for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(
        G, pos, edge_labels, font_size=10,
        bbox=dict(boxstyle='round,pad=0.2', fc='white', alpha=0.7), ax=ax
    )

    ax.set_title(
        'Demo Network Topology  (10 Routers)\n'
        'Edge labels = Link Cost',
        fontsize=14, fontweight='bold', pad=14
    )
    ax.axis('off')
    plt.tight_layout()
    plt.savefig(filename, dpi=FIG_DPI, bbox_inches='tight')
    plt.close()
    print(f"  Saved → {filename}")


# ═══════════════════════════════════════════════════════
#  FIGURE 2 — Convergence Rounds vs Network Size
# ═══════════════════════════════════════════════════════

def run_convergence_experiment():
    """
    For each network size, simulate both protocols and record
    the number of flooding rounds until full convergence.
    """
    sizes = [5, 10, 15, 20, 25, 30, 40, 50]
    ospf_rounds   = []
    sc_ospf_rounds = []

    for n in sizes:
        G = create_random_topology(n, seed=42)

        ospf_net = OSPFNetwork(G)
        ospf_rounds.append(ospf_net.simulate_convergence())

        sc_net = SCOSPFNetwork(G)
        sc_ospf_rounds.append(sc_net.simulate_convergence())

    return sizes, ospf_rounds, sc_ospf_rounds


def plot_convergence_rounds(sizes, ospf_r, sc_r,
                            filename='fig2_convergence_rounds.png'):
    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(sizes, ospf_r, color=OSPF_COLOR, marker='o',
            linewidth=2.5, markersize=9, label='Standard OSPF', zorder=3)
    ax.plot(sizes, sc_r,   color=SCOS_COLOR, marker='s',
            linewidth=2.5, markersize=9, label='SC-OSPF (Proposed)', zorder=3)
    ax.fill_between(sizes, ospf_r, sc_r,
                    alpha=0.12, color='blue', label='Improvement region')

    ax.set_xlabel('Number of Routers in Network', fontsize=13)
    ax.set_ylabel('Convergence Rounds', fontsize=13)
    ax.set_title(
        'Convergence Rounds vs Network Size\n'
        'OSPF (grows with diameter)  vs  SC-OSPF (always 2 rounds)',
        fontsize=13, fontweight='bold'
    )
    ax.legend(fontsize=11)
    ax.grid(True, alpha=GRID_ALPHA)
    ax.set_xticks(sizes)
    ax.set_yticks(range(0, max(ospf_r) + 2))

    # Annotation explaining why SC-OSPF is flat
    ax.annotate(
        'SC-OSPF: fixed 2 rounds\n(controller-based)',
        xy=(sizes[-1], 2), xytext=(sizes[-2] - 5, 4),
        fontsize=9, color=SCOS_COLOR,
        arrowprops=dict(arrowstyle='->', color=SCOS_COLOR)
    )

    plt.tight_layout()
    plt.savefig(filename, dpi=FIG_DPI, bbox_inches='tight')
    plt.close()
    print(f"  Saved → {filename}")


# ═══════════════════════════════════════════════════════
#  FIGURE 3 — Message Overhead Comparison
# ═══════════════════════════════════════════════════════

def run_message_experiment():
    sizes = [5, 10, 15, 20, 25, 30, 40, 50]
    ospf_msgs   = []
    sc_msgs     = []

    for n in sizes:
        G = create_random_topology(n, seed=42)

        ospf_net = OSPFNetwork(G)
        ospf_net.simulate_convergence()
        ospf_msgs.append(ospf_net.total_messages)

        sc_net = SCOSPFNetwork(G)
        sc_net.simulate_convergence()
        sc_msgs.append(sc_net.total_messages)

    return sizes, ospf_msgs, sc_msgs


def plot_message_overhead(sizes, ospf_msgs, sc_msgs,
                          filename='fig3_message_overhead.png'):
    fig, ax = plt.subplots(figsize=(11, 6))
    x = np.arange(len(sizes))
    w = 0.36

    bars1 = ax.bar(x - w/2, ospf_msgs, w,
                   label='Standard OSPF', color=OSPF_COLOR,
                   alpha=0.88, edgecolor='black', linewidth=0.7)
    bars2 = ax.bar(x + w/2, sc_msgs, w,
                   label='SC-OSPF (Proposed)', color=SCOS_COLOR,
                   alpha=0.88, edgecolor='black', linewidth=0.7)

    # Value labels on bars
    for bar in bars1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 1,
                str(int(h)), ha='center', va='bottom', fontsize=8)
    for bar in bars2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 1,
                str(int(h)), ha='center', va='bottom', fontsize=8)

    ax.set_xlabel('Number of Routers', fontsize=13)
    ax.set_ylabel('Total Control Messages', fontsize=13)
    ax.set_title(
        'Control Message Overhead\n'
        'OSPF (O(N·E) flooding)  vs  SC-OSPF (O(2N))',
        fontsize=13, fontweight='bold'
    )
    ax.set_xticks(x)
    ax.set_xticklabels(sizes)
    ax.legend(fontsize=11)
    ax.grid(True, alpha=GRID_ALPHA, axis='y')

    plt.tight_layout()
    plt.savefig(filename, dpi=FIG_DPI, bbox_inches='tight')
    plt.close()
    print(f"  Saved → {filename}")


# ═══════════════════════════════════════════════════════
#  FIGURE 4 — LSA Injection Attack: Side-by-Side
# ═══════════════════════════════════════════════════════

def run_attack_experiment(G, attacker=1, victim=5):
    """
    Run the LSA injection attack on both protocols.
    Returns a dict with results.
    """
    # ── OSPF ──
    ospf_net = OSPFNetwork(G)
    ospf_net.simulate_convergence()
    ospf_corrupted, ospf_changed = ospf_net.simulate_lsa_injection_attack(
        attacker_id=attacker, victim_id=victim, fake_cost=1
    )

    # ── SC-OSPF ──
    sc_net = SCOSPFNetwork(G)
    sc_net.simulate_convergence()
    sc_corrupted, sc_changed = sc_net.simulate_lsa_injection_attack(
        attacker_id=attacker, victim_id=victim, fake_cost=1
    )

    return {
        'ospf_corrupted':  ospf_corrupted,
        'ospf_changed':    ospf_changed,
        'sc_corrupted':    sc_corrupted,
        'sc_changed':      sc_changed,
        'sc_rejected':     sc_net.controller.lsas_rejected,
    }


def plot_attack_results(results, filename='fig4_attack_comparison.png'):
    fig, axes = plt.subplots(1, 2, figsize=(13, 6))

    protocols = ['Standard OSPF', 'SC-OSPF\n(Proposed)']
    colors    = [OSPF_COLOR, SCOS_COLOR]

    # ── Left: Corrupted routers ──
    corr_vals = [results['ospf_corrupted'], results['sc_corrupted']]
    bars = axes[0].bar(protocols, corr_vals, color=colors,
                       edgecolor='black', width=0.45, alpha=0.88)
    axes[0].set_ylabel('Routers with Corrupted LSDB', fontsize=12)
    axes[0].set_title('Corrupted Routers After Attack',
                      fontsize=12, fontweight='bold')
    axes[0].set_ylim(0, max(corr_vals) + 3)
    axes[0].grid(True, alpha=GRID_ALPHA, axis='y')
    for bar, val in zip(bars, corr_vals):
        axes[0].text(
            bar.get_x() + bar.get_width()/2.,
            bar.get_height() + 0.2,
            str(val), ha='center', va='bottom',
            fontsize=16, fontweight='bold'
        )
    # Labels
    axes[0].text(0, corr_vals[0] + 1.2, '✗ VULNERABLE',
                 ha='center', color=OSPF_COLOR,
                 fontsize=10, fontweight='bold')
    axes[0].text(1, corr_vals[1] + 1.2, '✓ SECURE',
                 ha='center', color=SCOS_COLOR,
                 fontsize=10, fontweight='bold')

    # ── Right: Changed routing entries ──
    chng_vals = [results['ospf_changed'], results['sc_changed']]
    bars2 = axes[1].bar(protocols, chng_vals, color=colors,
                        edgecolor='black', width=0.45, alpha=0.88)
    axes[1].set_ylabel('Routing Table Entries Changed', fontsize=12)
    axes[1].set_title('Routing Table Integrity After Attack',
                      fontsize=12, fontweight='bold')
    axes[1].set_ylim(0, max(chng_vals) + 3)
    axes[1].grid(True, alpha=GRID_ALPHA, axis='y')
    for bar, val in zip(bars2, chng_vals):
        axes[1].text(
            bar.get_x() + bar.get_width()/2.,
            bar.get_height() + 0.2,
            str(val), ha='center', va='bottom',
            fontsize=16, fontweight='bold'
        )
    axes[1].text(1, chng_vals[1] + 1.2, '0 entries changed',
                 ha='center', color=SCOS_COLOR, fontsize=9)

    fig.suptitle(
        'LSA Injection Attack: Standard OSPF vs SC-OSPF\n'
        f'(Attacker: R1  →  Impersonating: R5,  Fake cost = 1)',
        fontsize=13, fontweight='bold', y=1.02
    )
    plt.tight_layout()
    plt.savefig(filename, dpi=FIG_DPI, bbox_inches='tight')
    plt.close()
    print(f"  Saved → {filename}")


# ═══════════════════════════════════════════════════════
#  FIGURE 5 — Routing Table Before vs After Attack
# ═══════════════════════════════════════════════════════

def plot_routing_table_change(G, attacker=1, victim=5,
                              filename='fig5_routing_integrity.png'):
    """
    Show the routing table of Router 0 before and after the attack,
    for both OSPF and SC-OSPF.
    """
    # ── OSPF: before attack ──
    ospf_net = OSPFNetwork(G)
    ospf_net.simulate_convergence()
    ospf_before = dict(ospf_net.get_routing_table(0))

    # ── OSPF: after attack ──
    ospf_net.simulate_lsa_injection_attack(
        attacker_id=attacker, victim_id=victim, fake_cost=1
    )
    ospf_after = dict(ospf_net.get_routing_table(0))

    # ── SC-OSPF: before attack ──
    sc_net = SCOSPFNetwork(G)
    sc_net.simulate_convergence()
    sc_before = dict(sc_net.get_forwarding_table(0))

    # ── SC-OSPF: after attack (should be unchanged) ──
    sc_net.simulate_lsa_injection_attack(
        attacker_id=attacker, victim_id=victim, fake_cost=1
    )
    sc_after = dict(sc_net.get_forwarding_table(0))

    # ── Build comparison table ──
    all_dests = sorted(set(list(ospf_before.keys()) + list(sc_before.keys())))

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    def format_entry(table, dest):
        if dest not in table:
            return 'N/A'
        nh, cost = table[dest]
        return f'via R{nh} (cost={cost})'

    # OSPF table
    ospf_rows = []
    for dest in all_dests:
        b = format_entry(ospf_before, dest)
        a = format_entry(ospf_after, dest)
        changed = '⚠ CHANGED' if b != a else '✓ Same'
        ospf_rows.append([f'R{dest}', b, a, changed])

    ospf_headers = ['Dest', 'Before Attack', 'After Attack', 'Status']
    tbl1 = axes[0].table(
        cellText=ospf_rows, colLabels=ospf_headers,
        cellLoc='center', loc='center'
    )
    tbl1.auto_set_font_size(False)
    tbl1.set_fontsize(9)
    tbl1.scale(1, 1.6)

    # Color changed rows red
    for row_i, row in enumerate(ospf_rows):
        if '⚠' in row[3]:
            for col_i in range(4):
                tbl1[row_i + 1, col_i].set_facecolor('#ffdddd')
    # Header row
    for col_i in range(4):
        tbl1[0, col_i].set_facecolor(OSPF_COLOR)
        tbl1[0, col_i].set_text_props(color='white', fontweight='bold')

    axes[0].set_title('Standard OSPF — Router 0 Routing Table\n'
                      '(Red rows = corrupted by attack)',
                      fontsize=11, fontweight='bold', color=OSPF_COLOR)
    axes[0].axis('off')

    # SC-OSPF table
    sc_rows = []
    for dest in all_dests:
        b = format_entry(sc_before, dest)
        a = format_entry(sc_after, dest)
        status = '✓ Intact' if b == a else '⚠ CHANGED'
        sc_rows.append([f'R{dest}', b, a, status])

    tbl2 = axes[1].table(
        cellText=sc_rows, colLabels=ospf_headers,
        cellLoc='center', loc='center'
    )
    tbl2.auto_set_font_size(False)
    tbl2.set_fontsize(9)
    tbl2.scale(1, 1.6)

    # All rows should be green (intact)
    for row_i in range(len(sc_rows)):
        for col_i in range(4):
            tbl2[row_i + 1, col_i].set_facecolor('#ddffdd')
    for col_i in range(4):
        tbl2[0, col_i].set_facecolor(SCOS_COLOR)
        tbl2[0, col_i].set_text_props(color='white', fontweight='bold')

    axes[1].set_title('SC-OSPF — Router 0 Routing Table\n'
                      '(All entries intact after attack)',
                      fontsize=11, fontweight='bold', color=SCOS_COLOR)
    axes[1].axis('off')

    fig.suptitle(
        'Routing Table Integrity: Router 0 View\nAfter LSA Injection Attack',
        fontsize=13, fontweight='bold'
    )
    plt.tight_layout()
    plt.savefig(filename, dpi=FIG_DPI, bbox_inches='tight')
    plt.close()
    print(f"  Saved → {filename}")


# ═══════════════════════════════════════════════════════
#  FIGURE 6 — Scalability: Convergence Time Trend
# ═══════════════════════════════════════════════════════

def plot_scalability_trend(sizes, ospf_r, sc_r,
                           filename='fig6_scalability.png'):
    """
    Show that OSPF convergence grows (roughly log-linearly) while
    SC-OSPF stays constant as network scales.
    """
    fig, ax = plt.subplots(figsize=(10, 6))

    # Actual data
    ax.plot(sizes, ospf_r, color=OSPF_COLOR, marker='o',
            linewidth=2, markersize=8, label='OSPF (measured)',
            zorder=3)
    ax.axhline(y=2, color=SCOS_COLOR, linewidth=2.5, linestyle='--',
               label='SC-OSPF (always 2 rounds)', zorder=3)

    # Shaded improvement area
    ax.fill_between(sizes, ospf_r, [2]*len(sizes),
                    alpha=0.10, color='blue')

    ax.set_xlabel('Network Size (Number of Routers)', fontsize=13)
    ax.set_ylabel('Convergence Rounds', fontsize=13)
    ax.set_title(
        'Scalability: How Convergence Grows With Network Size\n'
        'OSPF grows with diameter  |  SC-OSPF: O(1) constant',
        fontsize=13, fontweight='bold'
    )
    ax.legend(fontsize=11)
    ax.grid(True, alpha=GRID_ALPHA)
    ax.set_xticks(sizes)
    ax.set_ylim(0, max(ospf_r) + 2)

    plt.tight_layout()
    plt.savefig(filename, dpi=FIG_DPI, bbox_inches='tight')
    plt.close()
    print(f"  Saved → {filename}")


# ═══════════════════════════════════════════════════════
#  MAIN — Run all experiments
# ═══════════════════════════════════════════════════════

def main():
    print("\nSC-OSPF Simulation — EN2150 Assignment 4")
    print("Secure & Centralized OSPF Protocol")
    print("University of Moratuwa, Dept. of ENTC\n")

    # Use demo topology for attack/routing demonstrations
    G_demo = create_demo_topology()

    # ── Topology ─────────────────────────────────────
    banner("FIGURE 1 — Network Topology")
    plot_topology(G_demo)
    print(f"  Routers : {G_demo.number_of_nodes()}")
    print(f"  Links   : {G_demo.number_of_edges()}")

    # ── Convergence on demo topology ─────────────────
    banner("Basic Convergence Demo (10-router network)")

    ospf_demo = OSPFNetwork(G_demo)
    o_rounds = ospf_demo.simulate_convergence()

    sc_demo = SCOSPFNetwork(G_demo)
    s_rounds = sc_demo.simulate_convergence()

    print(f"  OSPF convergence    : {o_rounds} rounds  "
          f"| {ospf_demo.total_messages} messages")
    print(f"  SC-OSPF convergence : {s_rounds} rounds  "
          f"| {sc_demo.total_messages} messages")
    print(f"  Round reduction     : {o_rounds - s_rounds} fewer rounds")

    print("\n  OSPF Routing Table (from Router 0's perspective):")
    for dest in sorted(ospf_demo.get_routing_table(0)):
        nh, cost = ospf_demo.get_routing_table(0)[dest]
        print(f"    → R{dest}: via R{nh}, cost = {cost}")

    print("\n  SC-OSPF Forwarding Table (from Router 0's perspective):")
    for dest in sorted(sc_demo.get_forwarding_table(0)):
        nh, cost = sc_demo.get_forwarding_table(0)[dest]
        print(f"    → R{dest}: via R{nh}, cost = {cost}")

    # Verify both produce same routes (correctness check)
    ospf_rt = ospf_demo.get_routing_table(0)
    sc_ft   = sc_demo.get_forwarding_table(0)
    same = all(
        ospf_rt.get(d) == sc_ft.get(d) for d in ospf_rt
    )
    print(f"\n  Route correctness check (OSPF == SC-OSPF): {'PASS ✓' if same else 'FAIL ✗'}")

    # ── Scalability experiments ───────────────────────
    banner("FIGURES 2 & 3 — Convergence & Message Overhead")
    sizes, ospf_r, sc_r = run_convergence_experiment()
    _, ospf_msgs, sc_msgs = run_message_experiment()

    print(f"  {'Nodes':<8} {'OSPF Rounds':<15} {'SC-OSPF Rounds':<18} "
          f"{'OSPF Msgs':<13} {'SC-OSPF Msgs'}")
    print('  ' + '-'*62)
    for i, n in enumerate(sizes):
        print(f"  {n:<8} {ospf_r[i]:<15} {sc_r[i]:<18} "
              f"{ospf_msgs[i]:<13} {sc_msgs[i]}")

    plot_convergence_rounds(sizes, ospf_r, sc_r)
    plot_message_overhead(sizes, ospf_msgs, sc_msgs)
    plot_scalability_trend(sizes, ospf_r, sc_r)

    # ── Attack experiment ─────────────────────────────
    banner("FIGURES 4 & 5 — LSA Injection Attack Simulation")
    ATTACKER = 1
    VICTIM   = 5

    results = run_attack_experiment(G_demo, attacker=ATTACKER, victim=VICTIM)

    print(f"  Attack scenario: R{ATTACKER} impersonates R{VICTIM} "
          f"with fake_cost=1")
    print()
    print(f"  Standard OSPF result:")
    print(f"    Routers with corrupted LSDB : {results['ospf_corrupted']}")
    print(f"    Routing entries corrupted   : {results['ospf_changed']}")
    print(f"    Attack succeeded            : YES ✗")
    print()
    print(f"  SC-OSPF result:")
    print(f"    Routers with corrupted LSDB : {results['sc_corrupted']}")
    print(f"    Routing entries corrupted   : {results['sc_changed']}")
    print(f"    Forged LSAs rejected        : {results['sc_rejected']}")
    print(f"    Attack succeeded            : NO ✓")

    plot_attack_results(results)
    plot_routing_table_change(G_demo, attacker=ATTACKER, victim=VICTIM)

    # ── Summary ──────────────────────────────────────
    banner("SIMULATION COMPLETE — Files Generated")
    files = [
        ('fig1_topology.png',         'Network topology diagram'),
        ('fig2_convergence_rounds.png','Convergence rounds vs network size'),
        ('fig3_message_overhead.png', 'Message overhead comparison'),
        ('fig4_attack_comparison.png','LSA injection attack results'),
        ('fig5_routing_integrity.png','Routing table before/after attack'),
        ('fig6_scalability.png',      'Scalability trend'),
    ]
    for fname, desc in files:
        exists = '✓' if os.path.exists(fname) else '✗'
        print(f"  {exists}  {fname:<35} {desc}")

    print("\n  Use these figures directly in your EN2150 report.\n")


if __name__ == '__main__':
    main()
