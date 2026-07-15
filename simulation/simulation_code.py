import csv, simpy, numpy as np, random, json, os

SIM_DURATION = 7200
N_RUNS       = 100
SEEDS        = list(range(N_RUNS))
EVSE_COUNTS  = [50, 100, 500, 1000]
N_EVSE_DEF   = 50

# ZTA overlay per-request delays (s)
MTLS_MEAN, MTLS_STD = 0.150, 0.030     
PE_MEAN             = 0.005           
OCSP_MEAN, OCSP_STD = 0.020, 0.005    
OCSP_CAPACITY       = 8              

MESSAGE_TIMEOUT    = 30               

# Attack inter-arrival means (s). Each process samples Exp(mean=interval).
S2_INT, S3_INT, S4_INT = 120, 90, 180
PEP_FAILURE_TIME = 3600

# PEP local watchdog (fast failure detector), distinct from the 60 s OCPP heartbeat
PEP_DETECT_MEAN, PEP_DETECT_STD, PEP_DETECT_FLOOR = 0.100, 0.015, 0.020

# S4 wireless-session handshake delay: downgrade-permissive vs TLS 1.3-enforced
S4_LEGACY_DELAY = (0.400, 0.080)
S4_TLS13_DELAY  = (0.250, 0.050)

MODES = ['B0', 'B1', 'B2', 'B3', 'ZTA']
# Block probability per (mode, scenario). Baselines: B0 none, B1 OCPP SecProfile 2/3,
# B2 TLS + firewall/VPN, B3 TLS + IDS; ZTA = auth + authorization + integrity + downgrade prevention.
BLOCK_PROB = {
    'B0':  {'S2': 0.00, 'S3': 0.00, 'S4': 0.00},
    'B1':  {'S2': 0.00, 'S3': 0.85, 'S4': 0.10},
    'B2':  {'S2': 0.50, 'S3': 0.70, 'S4': 0.30},
    'B3':  {'S2': 0.70, 'S3': 0.75, 'S4': 0.60},
    'ZTA': {'S2': 1.00, 'S3': 1.00, 'S4': 1.00},
}

# -------------- S1 --------------
def run_overhead(n_evse, seed, zta=True):
    np.random.seed(seed); random.seed(seed)
    env = simpy.Environment()
    ocsp = simpy.Resource(env, capacity=OCSP_CAPACITY)
    over = []
    def session(env):
        while True:
            if zta:
                mtls = max(0.01, np.random.normal(MTLS_MEAN, MTLS_STD))
                yield env.timeout(mtls)
                pe = np.random.exponential(PE_MEAN)
                yield env.timeout(pe)
                t0 = env.now
                with ocsp.request() as req:
                    yield req
                    svc = max(0.001, np.random.normal(OCSP_MEAN, OCSP_STD))
                    yield env.timeout(svc)
                ocsp_total = env.now - t0  
                over.append(mtls + pe + ocsp_total)
            else:
                over.append(0.0)
            yield env.timeout(random.uniform(30, 300))
    for i in range(n_evse):
        env.process(session(env))
    env.run(until=SIM_DURATION)
    return over

def run_burst(n_evse, seed, frac=0.5):
    np.random.seed(seed); random.seed(seed)
    env = simpy.Environment()
    ocsp = simpy.Resource(env, capacity=OCSP_CAPACITY)
    waits = []
    def burst_session(env):
        mtls = max(0.01, np.random.normal(MTLS_MEAN, MTLS_STD))
        yield env.timeout(mtls)
        yield env.timeout(np.random.exponential(PE_MEAN))
        t0 = env.now
        with ocsp.request() as req:
            yield req
            yield env.timeout(max(0.001, np.random.normal(OCSP_MEAN, OCSP_STD)))
        waits.append(env.now - t0)            # OCSP total incl. queueing
    n_burst = int(n_evse * frac)
    for i in range(n_burst):
        env.process(burst_session(env))
    env.run()
    return waits

# -------------- S2-S4 --------------
def run_attack(scenario, interval, mode, seed, n_evse=N_EVSE_DEF, per_evse=False):
    np.random.seed(seed); random.seed(seed)
    env = simpy.Environment()
    p = BLOCK_PROB[mode][scenario]
    cnt = {'tot': 0, 'blk': 0}
    def attacker(env):
        while True:
            yield env.timeout(np.random.exponential(interval))
            cnt['tot'] += 1
            if np.random.random() < p:
                cnt['blk'] += 1
    if per_evse:
        for i in range(n_evse):
            env.process(attacker(env))
    else:
        env.process(attacker(env))
    env.run(until=SIM_DURATION)
    rate = (cnt['blk'] / cnt['tot']) if cnt['tot'] else 0.0
    return {'total': cnt['tot'], 'blocked': cnt['blk'], 'rate': rate}

# -------------- S4 --------------
def run_s4_delay(seed, zta):
    np.random.seed(seed); random.seed(seed)
    mean, std = (S4_TLS13_DELAY if zta else S4_LEGACY_DELAY)
    vals = [max(0.05, np.random.normal(mean, std)) for _ in range(200)]
    return float(np.mean(vals)) * 1000.0

# -------------- S5 --------------
def run_failsecure(seed):
    """Inject one PEP failure and sample one assumed watchdog response delay.
    """
    np.random.seed(seed); random.seed(seed)
    env = simpy.Environment(); observation = {}
    def watchdog(env):
        yield env.timeout(PEP_FAILURE_TIME)
        injected_at = env.now
        delay = max(PEP_DETECT_FLOOR, np.random.normal(PEP_DETECT_MEAN, PEP_DETECT_STD))
        yield env.timeout(delay)
        observation.update(
            failure_time_s=injected_at,
            fail_secure_time_s=env.now,
            sampled_watchdog_delay_ms=delay * 1000.0,
        )
    env.process(watchdog(env)); env.run()
    return observation

def stats(a):
    a = np.asarray(a, float)
    return {'mean': float(a.mean()), 'sd': float(a.std(ddof=1)),
            'p50': float(np.percentile(a, 50)), 'p95': float(np.percentile(a, 95)),
            'p99': float(np.percentile(a, 99)), 'max': float(a.max())}
def boot_ci(a, nboot=2000, seed=12345):
    a = np.asarray(a, float); rng = np.random.default_rng(seed)
    m = [rng.choice(a, a.size, replace=True).mean() for _ in range(nboot)]
    return float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))

# -------------- run --------------
print(f"=== Monte Carlo ({N_RUNS} runs, seeds 0-{N_RUNS-1}) ===", flush=True)
raw_rows = []

# S1 overhead at default fleet + tail latency
over_all = []; over_by_seed = {}
for s in SEEDS:
    seed_values = np.asarray(run_overhead(N_EVSE_DEF, s, zta=True), float) * 1000.0
    over_by_seed[s] = seed_values
    over_all.extend(seed_values.tolist())
    raw_rows.append({
        'seed': s, 'scenario': 'S1', 'configuration': f'EVSE={N_EVSE_DEF}',
        'metric': 'mean_session_establishment_overhead',
        'value': float(seed_values.mean()), 'unit': 'ms',
        'n_observations': int(seed_values.size),
    })
over_all = np.asarray(over_all, float)
o = stats(over_all); o_ci = boot_ci(over_all)
print(f"[S1] overhead mean={o['mean']:.2f} ms | p50={o['p50']:.2f} p95={o['p95']:.2f} "
      f"p99={o['p99']:.2f} max={o['max']:.2f} | 95%CI {o_ci[0]:.2f}-{o_ci[1]:.2f}")
print(f"     = {o['mean']/1000/MESSAGE_TIMEOUT*100:.3f}% of OCPP MessageTimeout ({MESSAGE_TIMEOUT}s)")

# EVSE sensitivity (per-run mean overhead)
evse_rows = {}
for n in EVSE_COUNTS:
    per_run = []
    for s in SEEDS:
        vals = np.asarray(run_overhead(n, s, zta=True), float) * 1000.0
        per_run.append(float(vals.mean()))
        raw_rows.append({
            'seed': s, 'scenario': 'S1-sensitivity', 'configuration': f'EVSE={n}',
            'metric': 'mean_session_establishment_overhead',
            'value': float(vals.mean()), 'unit': 'ms',
            'n_observations': int(vals.size),
        })
    evse_rows[n] = (float(np.mean(per_run)), float(np.std(per_run, ddof=1)))
    print(f"[S1-sens] EVSE={n:4d}: overhead {evse_rows[n][0]:.2f} +/- {evse_rows[n][1]:.2f} ms")

# burst stress (OCSP queueing) at each fleet size
burst_rows = {}
for n in EVSE_COUNTS:
    w = []
    for s in SEEDS:
        seed_w = np.asarray(run_burst(n, s, frac=0.5), float) * 1000.0
        w.extend(seed_w.tolist())
        for metric, value in [('mean_ocsp_wait', seed_w.mean()), ('p95_ocsp_wait', np.percentile(seed_w, 95))]:
            raw_rows.append({
                'seed': s, 'scenario': 'S1-burst', 'configuration': f'EVSE={n};fraction=0.5',
                'metric': metric, 'value': float(value), 'unit': 'ms',
                'n_observations': int(seed_w.size),
            })
    w = np.asarray(w, float)
    burst_rows[n] = (float(w.mean()), float(np.percentile(w, 95)))
    print(f"[burst] EVSE={n:4d}: OCSP wait mean={burst_rows[n][0]:.2f} ms p95={burst_rows[n][1]:.2f} ms")

# S2-S4 block rate per mode
block = {}
for sc, interval, per_evse in [('S2', S2_INT, False), ('S3', S3_INT, True), ('S4', S4_INT, True)]:
    block[sc] = {}
    for m in MODES:
        outcomes = [run_attack(sc, interval, m, s, per_evse=per_evse) for s in SEEDS]
        rates = [outcome['rate'] * 100 for outcome in outcomes]
        for s, outcome in zip(SEEDS, outcomes):
            raw_rows.append({
                'seed': s, 'scenario': sc, 'configuration': m,
                'metric': 'illustrative_block_rate', 'value': outcome['rate'] * 100,
                'unit': 'percent', 'n_observations': outcome['total'],
            })
        rates = np.array(rates)
        ci = boot_ci(rates)
        block[sc][m] = (float(rates.mean()), float(rates.std(ddof=1)), ci[0], ci[1])
    line = " | ".join(f"{m}={block[sc][m][0]:.2f}%" for m in MODES)
    print(f"[{sc}] block: {line}")

# S4 delay
s4_zta = [run_s4_delay(s, True) for s in SEEDS]; s4_leg = [run_s4_delay(s, False) for s in SEEDS]
for s, legacy, tls13 in zip(SEEDS, s4_leg, s4_zta):
    raw_rows.extend([
        {'seed': s, 'scenario': 'S4-delay', 'configuration': 'legacy',
         'metric': 'mean_handshake_delay', 'value': legacy, 'unit': 'ms', 'n_observations': 200},
        {'seed': s, 'scenario': 'S4-delay', 'configuration': 'TLS1.3-enforced',
         'metric': 'mean_handshake_delay', 'value': tls13, 'unit': 'ms', 'n_observations': 200},
    ])
s4_zta_m, s4_leg_m = float(np.mean(s4_zta)), float(np.mean(s4_leg))
red = (s4_leg_m - s4_zta_m) / s4_leg_m * 100
print(f"[S4] wireless delay legacy={s4_leg_m:.2f} ms -> TLS1.3={s4_zta_m:.2f} ms ({-red:.1f}%)")

# S5: one model-input watchdog sample per injected failure (one failure/run)
s5_observations = [run_failsecure(s) for s in SEEDS]
det_all = np.asarray([row['sampled_watchdog_delay_ms'] for row in s5_observations], float)
for s, row in zip(SEEDS, s5_observations):
    raw_rows.append({
        'seed': s, 'scenario': 'S5', 'configuration': 'assumed-local-watchdog',
        'metric': 'sampled_watchdog_response_delay',
        'value': row['sampled_watchdog_delay_ms'], 'unit': 'ms', 'n_observations': 1,
    })
d = stats(det_all); d_ci = boot_ci(det_all)
print(f"[S5] assumed watchdog sample mean={d['mean']:.2f} ms p95={d['p95']:.2f} | "
      f"95%CI {d_ci[0]:.2f}-{d_ci[1]:.2f}")

# ---- save ----
HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.environ.get("ZTA_RESULTS_DIR") or os.path.join(HERE, "results")
os.makedirs(RES, exist_ok=True)
summary = {
    "n_runs": N_RUNS,
    "interpretation": {
        "S1": "Modeled session-establishment overhead under stated delay distributions.",
        "S2_S4": "Illustrative outcomes from assumed block probabilities; not empirical attack-blocking measurements.",
        "S5": "One draw per run from the assumed local-watchdog response distribution; not an implemented watchdog benchmark.",
        "anchor_scope": "Generic enforcement mechanisms represented by anchor designs; no independent traffic model for each anchor path.",
    },
    "S1_overhead_ms": o, "S1_overhead_ci": o_ci,
    "S1_overhead_pct_timeout": o['mean']/1000/MESSAGE_TIMEOUT*100,
    "EVSE_sensitivity": {str(k): v for k, v in evse_rows.items()},
    "burst_ocsp_wait": {str(k): v for k, v in burst_rows.items()},
    "block_rate": block,
    "S4_delay_legacy_ms": s4_leg_m, "S4_delay_tls13_ms": s4_zta_m, "S4_delay_reduction_pct": red,
    "S5_sampled_watchdog_delay_ms": d, "S5_sampled_watchdog_delay_ci": d_ci,
}
with open(os.path.join(RES, "simulation_summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)
with open(os.path.join(RES, "per_seed_results.csv"), "w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=['seed', 'scenario', 'configuration', 'metric', 'value', 'unit', 'n_observations'],
        lineterminator='\n',
    )
    writer.writeheader(); writer.writerows(raw_rows)
print("\nSaved:", os.path.join(RES, "simulation_summary.json"))
print("Saved:", os.path.join(RES, "per_seed_results.csv"))

if os.environ.get("ZTA_NO_FIGURES") != "1":
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    FIGDIR = RES
    C_ZTA, C_BASE = "#2b7bba", "#e8734a"
    BLUES = ["#c9d9e8", "#9cc0dc", "#6ba3d0", "#3d7cb8", "#1f4e79"]
    ns = EVSE_COUNTS

    # S1 overhead distribution (a) + tail latency (b)
    fig, ax = plt.subplots(1, 2, figsize=(10, 4.2))
    ax[0].hist(over_all, bins=60, color=C_ZTA, alpha=0.8)
    for pc, lab in [(o['p50'], 'p50'), (o['p95'], 'p95'), (o['p99'], 'p99')]:
        ax[0].axvline(pc, color='k', ls='--', lw=1)
        ax[0].text(pc, ax[0].get_ylim()[1]*0.9, f" {lab}\n {pc:.0f}", fontsize=8)
    ax[0].set_title("(a) S1: Session-establishment Overhead (100 seeded runs)")
    ax[0].set_xlabel("Overhead (ms)"); ax[0].set_ylabel("Count")
    labs = ['mean', 'p50', 'p95', 'p99', 'max']
    vals = [o['mean'], o['p50'], o['p95'], o['p99'], o['max']]
    b = ax[1].bar(labs, vals, color=BLUES)
    ax[1].bar_label(b, fmt='%.0f', fontsize=9)
    ax[1].set_title("(b) S1: Overhead Tail Latency"); ax[1].set_ylabel("Delay (ms)")
    plt.tight_layout()
    plt.savefig(os.path.join(FIGDIR, "overhead.png"), dpi=130, bbox_inches='tight'); plt.close()

    # S1 overhead vs EVSE count (fleet-size sensitivity)
    fig, ax = plt.subplots(figsize=(7, 4.4))
    ms = [evse_rows[n][0] for n in ns]; es = [evse_rows[n][1] for n in ns]
    ax.errorbar([str(n) for n in ns], ms, yerr=es, marker='o', color=C_ZTA, capsize=4, lw=2)
    ax.set_title("S1: Overhead vs EVSE Count (Sensitivity)")
    ax.set_xlabel("Number of EVSEs"); ax.set_ylabel("Overhead (ms)")
    for x, y in zip([str(n) for n in ns], ms):
        ax.text(x, y+0.8, f"{y:.1f}", ha='center', fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(FIGDIR, "evse_sensitivity.png"), dpi=130, bbox_inches='tight'); plt.close()

    # S4 TLS 1.3 handshake delay (a) + assumed S5 watchdog-delay samples (b)
    fig, ax = plt.subplots(1, 2, figsize=(11, 4.2))
    bb = ax[0].bar(["Legacy\n(downgrade-permissive)", "ZTA\n(TLS 1.3 enforced)"],
                   [s4_leg_m, s4_zta_m], color=[C_BASE, C_ZTA])
    ax[0].bar_label(bb, fmt='%.0f ms', fontsize=10)
    ax[0].set_title("(a) S4: Wireless Handshake Delay"); ax[0].set_ylabel("Delay (ms)")
    ax[1].hist(det_all, bins=40, color=C_ZTA, alpha=0.85)
    ax[1].axvline(d['mean'], color='k', ls='--'); ax[1].axvline(d['p95'], color='r', ls='--')
    ax[1].text(d['mean'], ax[1].get_ylim()[1]*0.85, f" mean {d['mean']:.0f}", fontsize=9)
    ax[1].text(d['p95'], ax[1].get_ylim()[1]*0.6, f" p95 {d['p95']:.0f}", fontsize=9, color='r')
    ax[1].set_title("(b) S5: Assumed Local-watchdog Delay Samples")
    ax[1].set_xlabel("Sampled response delay (ms)"); ax[1].set_ylabel("Count")
    plt.tight_layout()
    plt.savefig(os.path.join(FIGDIR, "tls_failsecure.png"), dpi=130, bbox_inches='tight'); plt.close()

    # burst: concurrent-burst OCSP responder queueing delay
    fig, ax = plt.subplots(figsize=(7, 4.4))
    bm = [burst_rows[n][0] for n in ns]; bp = [burst_rows[n][1] for n in ns]
    ax.plot([str(n) for n in ns], bm, marker='o', color=C_ZTA, lw=2, label='mean OCSP wait')
    ax.plot([str(n) for n in ns], bp, marker='s', color=C_BASE, lw=2, ls='--', label='p95 OCSP wait')
    ax.set_title("Concurrent-Burst OCSP Responder Queueing Delay")
    ax.set_xlabel("Number of EVSEs (50% simultaneous re-establish)")
    ax.set_ylabel("OCSP wait (ms)"); ax.legend()
    for x0, y in zip([str(n) for n in ns], bm):
        ax.text(x0, y+15, f"{y:.0f}", ha='center', fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(FIGDIR, "burst.png"), dpi=130, bbox_inches='tight'); plt.close()

    print("Saved figures")
