#!/usr/bin/env python3
"""Prepare, install, inspect or stop profile-scoped Linux systemd user services.

Prepare writes reviewable units only. Install starts the three selected units,
checks authenticated loopback health/manifests, then enables user persistence.
No model downloads, inference, application .env writes, shell commands or linger
changes are performed. User-service persistence follows the user manager's life.
"""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from runtimes.meld.manifest import strict_json, _model
SYSTEMCTL = '/usr/bin/systemctl'
ANALYZE = '/usr/bin/systemd-analyze'
FLOCK = '/usr/bin/flock'
HEX = re.compile(r'[0-9a-f]{64}\Z')
PROFILE_FILES = ('profile.json', 'owner.json', 'generation-manifest.json', 'review-manifest.json', 'owner-token', 'generation-token', 'review-token', 'meld.env')


def bounded(path, maximum=1024 * 1024):
    if path.stat().st_size > maximum:
        raise ValueError('profile file exceeds its size limit: ' + path.name)
    return path.read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(value, *, exists=True, directory=False, private=False, executable=None):
    path = Path(value)
    if not path.is_absolute() or any(unicodedata.category(c) == 'Cc' or c in '$%\\"' for c in str(path)):
        raise ValueError('absolute paths without control or systemd expansion characters are required')
    if executable:
        # Preserve a venv's Python symlink: resolving it changes sys.prefix.
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError('an existing executable is required: ' + str(path))
        names = {'llama': r'llama-server', 'nucleus': r'nucleus', 'python': r'python(?:3(?:\.\d+)?)?', 'php': r'php(?:8\.5)?'}
        if not re.fullmatch(names[executable], path.name):
            raise ValueError('unexpected executable name for ' + executable)
        return Path(os.path.abspath(path))
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('symlinked profile/model/service paths are forbidden')
    path = path.resolve()
    if exists:
        info = path.stat()
        if directory != stat.S_ISDIR(info.st_mode) or (not directory and not stat.S_ISREG(info.st_mode)):
            raise ValueError('unexpected profile path type: ' + str(path))
        if private and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError('profile paths must be owned and private: ' + path.name)
    return path


def private_write(path, data):
    if path.exists():
        safe_path(path, private=True)
        if bounded(path) == data:
            return
        raise ValueError('refusing to replace an existing file: ' + str(path))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as target:
        target.write(data)


def ensure_log(path):
    if path.exists():
        safe_path(path, private=True)
    else:
        private_write(path, b'')


def private_dir(path):
    if not path.exists():
        path.mkdir(mode=0o700)
    safe_path(path, directory=True, private=True)


def loopback_url(value):
    parsed = urllib.parse.urlsplit(value)
    try:
        valid = parsed.scheme == 'http' and ipaddress.ip_address(parsed.hostname).is_loopback
        port = parsed.port
    except (ValueError, TypeError):
        raise ValueError('literal loopback HTTP URL required') from None
    if not valid or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment or port is None:
        raise ValueError('bare literal loopback HTTP URL and explicit port required')
    return parsed.scheme + '://' + parsed.netloc, parsed.hostname, port


def load_profile(value):
    profile = safe_path(value, directory=True, private=True)
    raw = {name: bounded(safe_path(profile / name, private=True)) for name in PROFILE_FILES}
    config, owner = strict_json(raw['profile.json']), strict_json(raw['owner.json'])
    meld = owner['meld']
    gateway = loopback_url(config['gateway_url'])
    endpoints = {'gateway': gateway, 'generation': loopback_url(meld['generation_url']), 'review': loopback_url(meld['review_url'])}
    if len({item[2] for item in endpoints.values()}) != 3:
        raise ValueError('runtime and gateway ports must be distinct')
    tokens = {name: raw[('owner' if name == 'gateway' else name) + '-token'].decode().strip() for name in endpoints}
    if len(set(tokens.values())) != 3 or any(not HEX.fullmatch(token) for token in tokens.values()):
        raise ValueError('three distinct private 64-hex tokens are required')
    if owner['api_key'] != tokens['gateway'] or meld['generation_token'] != tokens['generation'] or meld['review_token'] != tokens['review']:
        raise ValueError('owner configuration and private token files differ')
    if config['shared_lock'] != str(profile / 'node-execution.lock'):
        raise ValueError('shared lock must belong to this private profile')
    models, manifests = {}, {}
    approvals = {}
    for approval in owner['approved_models']:
        if approval['sha256'] in approvals:
            raise ValueError('duplicate owner artifact approval')
        approvals[approval['sha256']] = approval
    for name, workload in [('generation', 'image-generation'), ('review', 'image-review')]:
        pin = digest(raw[name + '-manifest.json'])
        if not HEX.fullmatch(config[name + '_manifest_sha256']) or config[name + '_manifest_sha256'] != pin or meld[name + '_manifest_sha256'] != pin:
            raise ValueError('profile manifest bytes differ from pinned owner configuration')
        manifest = strict_json(raw[name + '-manifest.json'])
        allowed = {'sdxl_img2img', 'sdxl_readout'} if name == 'generation' else {'llama_cpp_vlm'}
        if manifest.get('schema_version') != 1 or manifest.get('artifact_set_complete') is not True or manifest.get('workload') != workload or manifest.get('backend') not in allowed:
            raise ValueError('unsupported complete local runtime manifest')
        if manifest['model'] != config[name + '_model'] or (name == 'review' and manifest['model'] != meld['review_model']):
            raise ValueError('profile model aliases differ')
        if not 1 <= len(manifest['artifacts']) <= 256:
            raise ValueError('invalid model artifact count')
        for artifact in manifest['artifacts']:
            model = artifact['model']
            _model(model, workload)  # Local metadata checks only; startup hashes files.
            approved = approvals.get(model['sha256'])
            if approved is None or approved['provenance'] != model['provenance']:
                raise ValueError('model artifact is not exactly owner-approved')
            if model['provenance']['lineage_complete'] is False:
                note = approved.get('review_note', '')
                if approved.get('allow_publisher_disclosed_lineage') is not True or not isinstance(note, str) or not note or note != note.strip() or len(note.encode()) > 2000 or any(unicodedata.category(c) == 'Cc' for c in note):
                    raise ValueError('publisher-disclosed artifact needs its exact owner exception and review note')
        model_root = safe_path(config[name + '_root'], directory=True)
        if profile.is_relative_to(model_root):
            raise ValueError('profile must be separate from immutable model roots')
        models[name], manifests[name] = model_root, manifest
    settings = {}
    for line in raw['meld.env'].decode().splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key in settings:
            raise ValueError('invalid private Meld environment profile')
        settings[key] = value
    expected = {'POSITRONIC_IMAGE_MAX_PIXELS': '262144', 'IMAGE_REVIEW_SOFT_ACCEPT': 'false',
                'POSITRONIC_IMAGE_TRANSPORT': 'nucleus', 'POSITRONIC_IMAGE_REVIEW_TRANSPORT': 'nucleus',
                'NUCLEUS_INFERENCE_API_KEY': tokens['gateway'], 'NUCLEUS_INFERENCE_BASE_URL': endpoints['gateway'][0],
                'POSITRONIC_IMAGE_BACKEND': manifests['generation']['backend'],
                'POSITRONIC_IMAGE_MODEL': manifests['generation']['model'], 'POSITRONIC_IMAGE_REVIEW_MODEL': manifests['review']['model'],
                'POSITRONIC_IMAGE_MANIFEST_SHA256': config['generation_manifest_sha256'],
                'POSITRONIC_IMAGE_REVIEW_MANIFEST_SHA256': config['review_manifest_sha256']}
    if any(settings.get(key) != value for key, value in expected.items()):
        raise ValueError('private Meld environment differs from bounded profile settings')
    return {'path': profile, 'raw': raw, 'config': config, 'owner': owner, 'endpoints': endpoints,
            'tokens': tokens, 'models': models, 'manifests': manifests, 'settings': settings}


def unit_names(profile, worker=False):
    tag = digest(str(profile).encode())[:12]
    kinds = ('generation', 'review', 'gateway', 'worker') if worker else ('generation', 'review', 'gateway')
    return {kind: 'nucleus-meld-' + tag + '-' + kind + '.service' for kind in kinds}


def validate_options(context, options):
    if not isinstance(options, dict) or set(options) - {'python', 'llama', 'nucleus', 'python_dependencies', 'fabric_port', 'php', 'meld_app', 'strength'}:
        raise ValueError('unsupported typed service options')
    strength = options.get('strength', 0.65)
    if type(strength) not in (int, float) or not math.isfinite(strength) or not 0 < strength <= 1:
        raise ValueError('strength must be a finite number within 0 < strength <= 1')
    port = options.get('fabric_port')
    if type(port) is not int or not 1 <= port <= 65535 or port in {endpoint[2] for endpoint in context['endpoints'].values()}:
        raise ValueError('fabric port must be a distinct integer within 1..65535')
    if bool(options.get('php')) != bool(options.get('meld_app')):
        raise ValueError('optional single worker requires both --php and --meld-app')
    if options.get('meld_app'):
        app = safe_path(options['meld_app'], directory=True)
        for relative in ('artisan', 'bootstrap/app.php', 'composer.json', 'vendor/autoload.php'):
            safe_path(app / relative)
        safe_path(options['php'], executable='php')
        settings = dict(line.partition('=')[::2] for line in context['raw']['meld.env'].decode().splitlines() if '=' in line)
        if settings.get('IMAGE_GENERATION_QUEUE_CONNECTION') != 'nucleus-media':
            raise ValueError('single worker requires private IMAGE_GENERATION_QUEUE_CONNECTION=nucleus-media')
        bounded_settings = {'POSITRONIC_IMAGE_STEPS': '30', 'POSITRONIC_IMAGE_GUIDANCE_SCALE': '5',
                            'IMAGE_REVIEW_MAX_ATTEMPTS': '1', 'POSITRONIC_IMAGE_TIMEOUT': '1800',
                            'POSITRONIC_IMAGE_REVIEW_TIMEOUT': '600'}
        if any(settings.get(key) != value for key, value in bounded_settings.items()) or settings.get('POSITRONIC_IMAGE_REVIEW_RETRY_DELAYS_MS') not in ('', '""', "''"):
            raise ValueError('single worker requires the reviewed 30/5/1 settings, generation1800/review600 and no review transport retries')


def runtime_timeout(context, kind):
    key = 'POSITRONIC_IMAGE_TIMEOUT' if kind == 'generation' else 'POSITRONIC_IMAGE_REVIEW_TIMEOUT'
    value = context['settings'].get(key, '1800')
    if not re.fullmatch(r'[0-9]{1,4}', value) or not 1 <= int(value) <= 1800:
        raise ValueError('runtime timeout must be an integer within 1..1800')
    return str(int(value))


def worker_lock_path(app):
    # This path is shared by all profiles for one canonical Meld application.
    # flock creates it privately when the supervised worker starts; prepare has
    # no runtime-directory writes. --no-fork retains the lock during job drain.
    return Path('/run/user') / str(os.geteuid()) / ('nucleus-meld-queue-' + digest(str(app).encode())[:20] + '.lock')


def quote(value):
    # safe_path rejects expansion/control characters; every ExecStart argument
    # here is fixed or a validated path/integer/pin. No shell is involved.
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def units(context, options):
    profile = context['path']
    validate_options(context, options)
    names = unit_names(profile, worker=bool(options.get('meld_app')))
    safe_path(ROOT, directory=True)
    binaries = {name: safe_path(options[name], executable=name) for name in ('python', 'llama', 'nucleus')}
    dependency = safe_path(options['python_dependencies'], directory=True) if options.get('python_dependencies') else None
    paths = {'generation': profile / 'generation-jobs', 'review': profile / 'review-jobs'}
    environment = {'PYTHONPATH': ':'.join(str(x) for x in (dependency, ROOT) if x), 'PYTHONUNBUFFERED': '1',
                   'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1', 'HF_HUB_DISABLE_TELEMETRY': '1',
                   'HF_HOME': str(profile / 'offline-cache'), 'DO_NOT_TRACK': '1', 'CUDA_VISIBLE_DEVICES': '-1',
                   'TOKENIZERS_PARALLELISM': 'false', 'OMP_NUM_THREADS': '4', 'MKL_NUM_THREADS': '4',
                   'OPENBLAS_NUM_THREADS': '4', 'NUMEXPR_NUM_THREADS': '4'}
    clean = 'HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy HF_TOKEN HUGGING_FACE_HUB_TOKEN NUCLEUS_INFERENCE_API_KEY POSITRONIC_IMAGE_API_TOKEN NUCLEUS_MELD_RUNTIME_TOKEN'
    result = {}
    for kind in ('generation', 'review', 'gateway'):
        if kind == 'gateway':
            command = [binaries['nucleus'], 'run', '--listen', '127.0.0.1:' + str(options['fabric_port']), '--no-open',
                       '--inference', profile / 'owner.json', '--inference-api', ('[' + context['endpoints']['gateway'][1] + ']' if ':' in context['endpoints']['gateway'][1] else context['endpoints']['gateway'][1]) + ':' + str(context['endpoints']['gateway'][2])]
            env = {**environment, 'NUCLEUS_HOME': str(profile / 'owner-state')}
            relations = 'Wants=' + names['generation'] + ' ' + names['review'] + '\nAfter=' + names['generation'] + ' ' + names['review'] + '\n'
        else:
            command = [binaries['python'], '-m', 'runtimes.meld.server', '--manifest', profile / (kind + '-manifest.json'),
                       '--manifest-sha256', context['config'][kind + '_manifest_sha256'], '--model-root', context['models'][kind],
                       '--token-file', profile / (kind + '-token'), '--host', context['endpoints'][kind][1],
                       '--port', str(context['endpoints'][kind][2]), '--device', 'cpu', '--threads', '4',
                       '--memory-limit-bytes', str((40 if kind == 'generation' else 8) * 1024**3),
                       '--reserve-memory-bytes', str(4 * 1024**3), '--timeout-seconds', runtime_timeout(context, kind),
                       '--upload-timeout-seconds', '30', '--max-pixels', '262144', '--strength', str(options.get('strength', 0.65)),
                       '--shared-lock', profile / 'node-execution.lock', '--work-dir', paths[kind]]
            if kind == 'review':
                command += ['--llama-binary', binaries['llama'], '--context-length', '4096', '--max-tokens', '256']
            env, relations = environment, ''
        result[names[kind]] = ('[Unit]\nDescription=Nucleus private Meld ' + kind + '\n' + relations +
            'StartLimitIntervalSec=300\nStartLimitBurst=3\n\n[Service]\nType=simple\nWorkingDirectory=' + str(ROOT) + '\n' +
            ''.join('Environment=' + quote(key + '=' + value) + '\n' for key, value in env.items()) +
            'UnsetEnvironment=' + clean + '\nExecStart=' + ' '.join(quote(arg) for arg in command) + '\n' +
            'UMask=0077\nKillMode=control-group\nTimeoutStopSec=10\nRestart=on-failure\nRestartSec=5\nNice=10\n' +
            'StandardOutput=append:' + str(profile / 'logs' / (kind + '.log')) + '\nStandardError=inherit\n\n[Install]\nWantedBy=default.target\n').encode()
    if 'worker' in names:
        app = safe_path(options['meld_app'], directory=True)
        php = safe_path(options['php'], executable='php')
        env_file = profile / 'meld.env'
        worker_env = environment
        worker_clean = clean.replace('NUCLEUS_INFERENCE_API_KEY', '') + ' OPENAI_API_KEY MODAL_TOKEN_ID MODAL_TOKEN_SECRET'
        prerequisites = [
            [binaries['python'], ROOT / 'scripts/manage_meld_media.py', 'wait-health', '--profile', profile],
            [php, app / 'artisan', 'meld:check-nucleus-profile', '--env-file=' + str(env_file)],
        ]
        if not Path(FLOCK).is_file() or not os.access(FLOCK, os.X_OK):
            raise ValueError('the existing Linux flock executable is required for a single worker')
        command = [FLOCK, '--no-fork', '--exclusive', '--nonblock', '--conflict-exit-code', '73', worker_lock_path(app), php, app / 'artisan', 'queue:work', 'nucleus-media', '--queue=nucleus-media', '--sleep=1', '--tries=1', '--timeout=5400', '--memory=512']
        result[names['worker']] = ('[Unit]\nDescription=Single Nucleus Meld media queue worker\nWants=' + ' '.join(names[kind] for kind in ('generation', 'review', 'gateway')) + '\nAfter=' + ' '.join(names[kind] for kind in ('generation', 'review', 'gateway')) +
            '\nStartLimitIntervalSec=300\nStartLimitBurst=3\n\n[Service]\nType=simple\nWorkingDirectory=' + str(app) + '\n' +
            ''.join('Environment=' + quote(key + '=' + value) + '\n' for key, value in worker_env.items()) +
            'EnvironmentFile=' + str(env_file) + '\nUnsetEnvironment=' + worker_clean + '\n' +
            ''.join('ExecStartPre=' + ' '.join(quote(arg) for arg in command) + '\n' for command in prerequisites) +
            'ExecStart=' + ' '.join(quote(arg) for arg in command) + '\nUMask=0077\nKillMode=control-group\nTimeoutStopSec=5460\nRestart=on-failure\nRestartSec=5\nNice=10\nStandardOutput=append:' + str(profile / 'logs/worker.log') + '\nStandardError=inherit\n\n[Install]\nWantedBy=default.target\n').encode()
    return result


def prepare(profile, options):
    context = load_profile(profile)
    profile = context['path']
    validate_options(context, options)
    rendered = units(context, options)  # Validate all inputs before writing.
    for subdir in ('systemd', 'logs', 'generation-jobs', 'review-jobs', 'offline-cache'):
        private_dir(profile / subdir)
    for kind in unit_names(profile, worker=bool(options.get('meld_app'))):
        ensure_log(profile / 'logs' / (kind + '.log'))
    for name, content in rendered.items():
        private_write(profile / 'systemd' / name, content)
    plan = {'schema_version': 1, 'profile': str(profile), 'options': options,
            'profile_files': {name: digest(raw) for name, raw in context['raw'].items()},
            'units': {name: digest(raw) for name, raw in rendered.items()},
            'readout_guided_callback_cap': 4, 'threads': 4, 'device': 'cpu', 'generation_as_bytes': 40 * 1024**3, 'review_as_bytes': 8 * 1024**3, 'reserve_bytes': 4 * 1024**3, 'scope': 'local CPU systemd user services; no linger changes'}
    private_write(profile / 'systemd' / 'plan.json', (json.dumps(plan, indent=2) + '\n').encode())
    return plan


def reviewed_plan(profile):
    context = load_profile(profile)
    plan = strict_json(bounded(safe_path(context['path'] / 'systemd/plan.json', private=True)))
    if plan.get('schema_version') != 1 or plan.get('profile') != str(context['path']) or plan.get('profile_files') != {name: digest(raw) for name, raw in context['raw'].items()}:
        raise ValueError('profile changed since unit preparation; use a fresh reviewed profile')
    for subdir in ('systemd', 'logs', 'generation-jobs', 'review-jobs', 'offline-cache'):
        safe_path(context['path'] / subdir, directory=True, private=True)
    for kind in unit_names(context['path'], worker=bool(plan['options'].get('meld_app'))):
        safe_path(context['path'] / 'logs' / (kind + '.log'), private=True)
    rendered = units(context, plan['options'])
    if plan.get('units') != {name: digest(raw) for name, raw in rendered.items()}:
        raise ValueError('prepared service plan differs from validated fixed commands')
    for name, content in rendered.items():
        if bounded(safe_path(context['path'] / 'systemd' / name, private=True)) != content:
            raise ValueError('prepared service unit changed after review')
    return context, plan, rendered


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ValueError('loopback service health redirects are forbidden')


def health_once(context):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
    for kind, (url, _host, _port) in context['endpoints'].items():
        suffix = '/healthz' if kind == 'gateway' else '/v1/runtime-manifest'
        request = urllib.request.Request(url + suffix, headers={'Authorization': 'Bearer ' + context['tokens'][kind]})
        with opener.open(request, timeout=2) as response:
            raw = response.read(1024 * 1024 + 1)
            if response.status != 200 or len(raw) > 1024 * 1024:
                raise ValueError('invalid bounded service health response')
            if kind == 'gateway':
                value = strict_json(raw)
                if not isinstance(value, dict) or value.get('service') != 'nucleus-inference' or value.get('state') != 'gateway_online':
                    raise ValueError('wrong owner gateway health identity')
            elif raw != context['raw'][kind + '-manifest.json'] or response.headers.get('X-Nucleus-Manifest-SHA256') != context['config'][kind + '_manifest_sha256']:
                raise ValueError('runtime health differs from its approved manifest pin')


def user_environment():
    env = os.environ.copy()
    runtime = Path('/run/user') / str(os.geteuid())
    if runtime.is_dir() and runtime.stat().st_uid == os.geteuid():
        env.setdefault('XDG_RUNTIME_DIR', str(runtime))
        env.setdefault('DBUS_SESSION_BUS_ADDRESS', 'unix:path=' + str(runtime / 'bus'))
    return env


def wait_health(context, timeout=60):
    deadline = time.monotonic() + timeout
    while True:
        try:
            health_once(context)
            return
        except (OSError, ValueError, urllib.error.URLError):
            if time.monotonic() >= deadline:
                raise RuntimeError('authenticated loopback health failed; persistence was not enabled') from None
            time.sleep(0.5)


def disable_and_stop(names, *, check=True):
    if any(name.endswith('-worker.service') for name in names):
        # systemd reverses After= ordering on shutdown. The worker receives
        # SIGTERM and drains its current job before core services are stopped.
        systemctl(['disable', *names], check=check)
        systemctl(['stop', '--no-block', *names], check=check)
    else:
        systemctl(['disable', '--now', *names], check=check)


def systemctl(arguments, *, check=True):
    return subprocess.run([SYSTEMCTL, '--user', *arguments], check=check, text=True, capture_output=True, timeout=45, env=user_environment())


def user_unit_directory():
    expected = Path.home() / '.config'
    if os.environ.get('XDG_CONFIG_HOME', str(expected)) != str(expected):
        raise ValueError('nondefault XDG_CONFIG_HOME requires manual unit installation')
    return safe_path(expected / 'systemd/user', exists=False, directory=True)


def assert_single_worker(context, plan, destination):
    app_value = plan['options'].get('meld_app')
    if not app_value:
        return
    app = safe_path(app_value, directory=True)
    selected = unit_names(context['path'], worker=True)['worker']
    # Include loaded units even if their unit file was removed during a drain.
    result = systemctl(['list-units', '--all', '--plain', '--no-legend', 'nucleus-meld-*-worker.service'])
    candidates = {line.split()[0] for line in result.stdout.splitlines() if line.split()}
    if destination.exists():
        candidates.update(path.name for path in destination.glob('nucleus-meld-*-worker.service'))
    for name in sorted(candidates):
        if name == selected or not re.fullmatch(r'nucleus-meld-[0-9a-f]{12}-worker\.service', name):
            continue
        result = systemctl(['show', name, '--property=WorkingDirectory,ActiveState,UnitFileState'])
        fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if fields.get('WorkingDirectory') != str(app):
            continue
        active = fields.get('ActiveState') not in ('inactive', 'failed')
        enabled = fields.get('UnitFileState') not in ('disabled', 'static', 'masked', 'not-found', '')
        if active or enabled:
            raise ValueError('another managed worker for this Meld app/nucleus-media queue is active or enabled: ' + name + '; explicitly drain and disable its old profile before installing this one')
    # The shared flock in ExecStart also closes simultaneous-install and manual
    # start races. No unrelated service is stopped or disabled by this guard.


def install(profile):
    context, plan, rendered = reviewed_plan(profile)
    profile = context['path']
    destination = user_unit_directory()
    assert_single_worker(context, plan, destination)
    # Refuse conflicting units before creating identity or touching systemd.
    for name, raw in rendered.items():
        target = destination / name
        if target.exists() and bounded(safe_path(target, private=True)) != raw:
            raise ValueError('refusing to overwrite an unrelated existing user unit: ' + name)
    for host, port in [(item[1], item[2]) for item in context['endpoints'].values()] + [('127.0.0.1', plan['options']['fabric_port'])]:
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((host, port))  # Never kill or adopt an existing listener.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith(('NUCLEUS_', 'HF_')) and 'PROXY' not in key.upper()}
    env['NUCLEUS_HOME'] = str(profile / 'owner-state')
    state_home = safe_path(profile / 'owner-state', exists=False, directory=True)
    if state_home.exists():
        safe_path(state_home, directory=True, private=True)
    log = profile / 'logs/bootstrap.log'
    ensure_log(log)
    state = state_home / 'state.json'
    with log.open('ab') as output:
        subprocess.run([plan['options']['nucleus'], 'init', '--name', 'meld-media-owner'], cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=30, check=True)
        disk = strict_json(bounded(safe_path(state, private=True)))
        public = disk['public']
        endpoint = 'https://127.0.0.1:' + str(plan['options']['fabric_port'])
        if public.get('fabric_id'):
            if public.get('owner_id') != public.get('node_id') or public.get('endpoint') != endpoint:
                raise ValueError('existing profile identity is not the selected loopback owner')
        else:
            subprocess.run([plan['options']['nucleus'], 'invite', '--endpoint', endpoint, '--out', str(profile / 'bootstrap-invitation.json')], cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=30, check=True)
    destination.mkdir(parents=True, exist_ok=True)
    info = destination.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('user unit directory must be owned and not writable by other users')
    for name, raw in rendered.items():
        private_write(destination / name, raw)
    systemctl(['daemon-reload'])
    names = list(rendered)
    try:
        core = [name for name in names if not name.endswith('-worker.service')]
        systemctl(['start', *core])
        wait_health(context)
        worker = [name for name in names if name.endswith('-worker.service')]
        if worker:
            systemctl(['start', *worker])
        systemctl(['enable', *names])
    except BaseException:
        disable_and_stop(names, check=False)
        raise
    return names


def selected_units(profile):
    path = safe_path(profile, directory=True, private=True)
    optional = unit_names(path, worker=True)['worker']
    return list(unit_names(path, worker=(path / 'systemd' / optional).is_file()).values())


def status(profile):
    names = selected_units(profile)
    result = systemctl(['show', *names, '--property=Id,ActiveState,SubState,UnitFileState,Result,MainPID'], check=False)
    return result.stdout


def stop(profile):
    names = selected_units(profile)
    disable_and_stop(names)
    return names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'install', 'status', 'stop', 'wait-health'))
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--python')
    parser.add_argument('--llama')
    parser.add_argument('--nucleus')
    parser.add_argument('--python-dependencies')
    parser.add_argument('--php', help='Optional explicit PHP8.5 executable; requires --meld-app')
    parser.add_argument('--meld-app', help='Optional existing Meld app with dependencies and nucleus-media queue/preflight')
    parser.add_argument('--fabric-port', type=int, default=19461)
    parser.add_argument('--strength', type=float, default=0.65, help='Explicit img2img strength within 0 < strength <= 1; Readout can use 1')
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            if not all((args.python, args.llama, args.nucleus)):
                parser.error('prepare requires explicit existing --python, --llama and --nucleus executable paths')
            options = {name: getattr(args, name) for name in ('python', 'llama', 'nucleus', 'python_dependencies', 'fabric_port', 'php', 'meld_app', 'strength')}
            plan = prepare(args.profile, options)
            print('Prepared reviewable private units: ' + str(args.profile / 'systemd'))
            print('No units installed, services started, identity initialized or application environment changed.')
            print('Units: ' + ', '.join(plan['units']))
        elif args.action == 'install':
            print('Started, health-checked and enabled user units: ' + ', '.join(install(args.profile)))
        elif args.action == 'wait-health':
            wait_health(load_profile(args.profile))
            print('Authenticated pinned loopback services are ready; no model was executed.')
        elif args.action == 'status':
            print(status(args.profile), end='')
        else:
            print('Disabled persistence and requested stop/drain of selected profile units: ' + ', '.join(stop(args.profile)))
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, type(error).__name__ + ': ' + str(error) + '\n')


if __name__ == '__main__':
    main()
