#!/usr/bin/env node
/*
 * image-sbom.js -- the SBOM (CycloneDX 1.6) of a published SNIF Connector image.
 *
 *   node docker/image-sbom.js [--digest sha256:HEX] IMAGE:VERSION > snif-<version>-image.cdx.json
 *   DOCKER="sudo docker" node docker/image-sbom.js ghcr.io/vesvault/snif:1.15 > snif-1.15-image.cdx.json
 *
 * Run it from a snif checkout that has the release tag v<VERSION>: the
 * image's revision label must be that tag's commit, and the Dockerfile is
 * read at it. Everything else is read from the published image. Nothing in
 * the image is run, so no platform needs emulation: for each platform the
 * index lists, a container is created (not started), and three files are
 * copied out of it:
 *
 *   - /lib/apk/db/installed: every Alpine package, as a pkg:apk purl with
 *     the Alpine release from os-release (distro=alpine-X.Y.Z) and, where
 *     the package was built from another, its origin (upstream=openssl for
 *     libssl3). OSV indexes Alpine by origin, so the matching needs both
 *   - /etc/os-release, the Alpine release
 *   - /usr/bin/snifd, the connector, hashed per platform
 *
 * The image is named by its index digest (one for all platforms), which is
 * what `docker pull ghcr.io/vesvault/snif:<version>` resolves. One SBOM covers
 * every platform, so the platforms must hold the same packages at the same
 * versions; their architectures differ, so the purls carry none.
 * Deterministic: no timestamp, and the serial number is derived from the
 * content, so the same image gives the same SBOM.
 *
 * It stops, writing nothing, if what it reads does not hold together: the
 * platforms differ in packages, Alpine release or labels; the revision is not
 * the tag's commit; the Alpine release is not the Dockerfile's; a package the
 * Dockerfile installs is missing; or --digest is not the image's.
 */
'use strict';
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const usage = () => {
    process.stderr.write('usage: node docker/image-sbom.js [--digest sha256:HEX] IMAGE:VERSION\n');
    process.exit(64);
};
let image, optDigest;
for (const argv = process.argv.slice(2); argv.length;) {
    const a = argv.shift();
    if (a === '--digest' && argv.length) optDigest = argv.shift();
    else if (!a.startsWith('-') && !image) image = a;
    else usage();
}
if (!image) usage();
if (optDigest && !/^sha256:[0-9a-f]{64}$/.test(optDigest)) usage();
const im = image.match(/^([a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._/-]+):([0-9]+(?:\.[0-9]+)+)$/);
if (!im) die(`${image} is not REGISTRY/REPOSITORY:VERSION`);
const [, repo, tagVersion] = im;

const docker = (process.env.DOCKER || 'docker').split(' ').filter(Boolean);
const run = (cmd, args, opts) => execFileSync(cmd, args,
    Object.assign({ encoding: 'utf8', maxBuffer: 64 << 20, stdio: ['ignore', 'pipe', 'inherit'] }, opts));
const dk = (args, opts) => run(docker[0], docker.slice(1).concat(args), opts);
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
function die(msg) { process.stderr.write(`image-sbom: ${msg}\n`); process.exit(1); }
const enc = (s) => encodeURIComponent(s);

// ---- the index: its digest, and the platform images in it
// The registry's bytes, hashed as they come: the digest is their SHA-256.
const raw = dk(['buildx', 'imagetools', 'inspect', '--raw', image], { encoding: 'buffer' });
const digest = `sha256:${sha256(raw)}`;
if (optDigest && optDigest !== digest) die(`${image} is ${digest}, not ${optDigest}`);
const index = JSON.parse(raw.toString('utf8'));
const INDEX = ['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json'];
if (!INDEX.includes(index.mediaType)) die(`${image} is not a multi-platform index (${index.mediaType})`);
// buildx's provenance attestations are manifests too, for platform unknown/unknown.
const plats = (index.manifests || [])
    .filter((m) => m.platform && m.platform.os !== 'unknown'
        && !((m.annotations || {})['vnd.docker.reference.type'] === 'attestation-manifest'))
    .map((m) => ({ digest: m.digest, name: [m.platform.os, m.platform.architecture, m.platform.variant].filter(Boolean).join('/') }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
if (!plats.length) die(`${image}: the index lists no platform image`);
for (const p of plats) if (!/^sha256:[0-9a-f]{64}$/.test(p.digest) || !/^[a-z0-9/]+$/.test(p.name)) die(`unexpected index entry ${p.name} ${p.digest}`);

// ---- each platform's files, from a container that is created and never started
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'snif-image-sbom-'));
const FILES = [['/lib/apk/db/installed', 'installed', false], ['/etc/os-release', 'os-release', true], ['/usr/bin/snifd', 'snifd', false]];
const parseKV = (text) => Object.fromEntries(text.split('\n')
    .map((l) => l.match(/^([A-Z_]+)=("?)(.*)\2$/)).filter(Boolean).map((x) => [x[1], x[3]]));
// apk's database: one paragraph per package, one letter per field (P name,
// V version, A arch, o origin, c the aports commit it was built from).
const parseApk = (text) => text.split(/\n\n+/).map((para) => {
    const f = {};
    for (const l of para.split('\n')) {
        const m = l.match(/^([A-Za-z]):(.*)$/);
        if (m && !(m[1] in f)) f[m[1]] = m[2];
    }
    return f;
}).filter((f) => f.P && f.V);
try {
    for (const p of plats) {
        const ref = `${repo}@${p.digest}`;
        const dir = path.join(tmp, p.name.replace(/\//g, '_'));
        fs.mkdirSync(dir);
        dk(['pull', '-q', '--platform', p.name, ref]);
        const info = JSON.parse(dk(['image', 'inspect', ref]))[0];
        const got = [info.Os, info.Architecture, info.Variant].filter(Boolean).join('/');
        if (got !== p.name) die(`${ref} is ${got}, the index says ${p.name}`);
        p.labels = (info.Config && info.Config.Labels) || {};
        const cid = dk(['create', '--platform', p.name, ref]).trim();
        try {
            for (const [src, , follow] of FILES) {
                if (/[^A-Za-z0-9/._-]/.test(src + cid + dir)) die(`unexpected characters in ${src} ${cid} ${dir}`);
                // A tar stream unpacked by this process: with DOCKER="sudo docker" a
                // plain `docker cp` would leave root's files this user cannot remove.
                run('bash', ['-o', 'pipefail', '-c', `${docker.join(' ')} cp ${follow ? '-L ' : ''}${cid}:${src} - | tar -xf - -C ${dir}`]);
            }
        } finally {
            dk(['rm', '-f', cid]);
        }
        for (const [src, local] of FILES) if (!fs.existsSync(path.join(dir, local))) die(`${src} did not come out of ${ref}`);
        p.osr = parseKV(fs.readFileSync(path.join(dir, 'os-release'), 'utf8'));
        p.pkgs = parseApk(fs.readFileSync(path.join(dir, 'installed'), 'utf8'));
        p.snifd = sha256(fs.readFileSync(path.join(dir, 'snifd')));
    }
} finally {
    fs.rmSync(tmp, { recursive: true, force: true });
}

// ---- the platforms agree, and agree with the release
const first = plats[0];
const same = (f, what) => {
    for (const p of plats) if (f(p) !== f(first)) die(`${what} differs: ${first.name} ${f(first)}, ${p.name} ${f(p)}`);
};
same((p) => p.osr.ID, 'the distribution');
same((p) => p.osr.VERSION_ID, 'the Alpine release');
same((p) => p.labels['org.opencontainers.image.version'], 'the version label');
same((p) => p.labels['org.opencontainers.image.revision'], 'the revision label');
const pkgSet = (p) => p.pkgs.map((f) => `${f.P}@${f.V}`).sort().join(' ');
same(pkgSet, 'the package set');
const osr = first.osr;
if (osr.ID !== 'alpine') die(`the image is ${osr.ID}, not alpine`);
const version = first.labels['org.opencontainers.image.version'];
const revision = first.labels['org.opencontainers.image.revision'];
if (version !== tagVersion) die(`${image} is labelled version ${version}`);
if (!/^[0-9a-f]{40}$/.test(revision || '')) die(`${image} has no revision label`);
const git = (args, what) => {
    try { return run('git', args, { stdio: ['ignore', 'pipe', 'ignore'] }); } catch (e) { return die(`${what} (run it from a snif checkout with the release tags)`); }
};
const tagCommit = git(['rev-parse', '-q', '--verify', `refs/tags/v${version}^{commit}`], `no tag v${version} here`).trim();
if (tagCommit !== revision) die(`${image} is labelled revision ${revision}; tag v${version} is ${tagCommit}`);
const dockerfile = git(['show', `${revision}:Dockerfile`], `no commit ${revision} here`);
const alpine = [...dockerfile.matchAll(/^FROM\s+alpine:(\S+)/gm)].map((x) => x[1]);
if (!alpine.length || alpine.some((t) => t !== alpine[0])) die(`the Dockerfile at ${revision} names Alpine ${alpine.join(', ') || 'nowhere'}`);
if (osr.VERSION_ID !== alpine[0] && !osr.VERSION_ID.startsWith(`${alpine[0]}.`)) die(`the image is Alpine ${osr.VERSION_ID}, the Dockerfile's ${alpine[0]}`);
const stages = dockerfile.split(/^FROM\s/m);
const wanted = ((stages[stages.length - 1].match(/apk add --no-cache ([^\\&\n]+)/) || [])[1] || '').trim().split(/\s+/).filter(Boolean);
if (!wanted.length) die(`no apk add in the Dockerfile's last stage at ${revision}`);
const byName = new Map(first.pkgs.map((f) => [f.P, f]));
for (const w of wanted) if (!byName.has(w)) die(`the Dockerfile installs ${w}, which the image does not have`);

// ---- the document
const distro = `alpine-${osr.VERSION_ID}`;
const pkgs = first.pkgs.slice().sort((a, b) => (a.P < b.P ? -1 : a.P > b.P ? 1 : 0)).map((f) => {
    const q = [`distro=${enc(distro)}`];
    if (f.o && f.o !== f.P) q.push(`upstream=${enc(f.o)}`);
    const purl = `pkg:apk/alpine/${enc(f.P)}@${enc(f.V)}?${q.join('&')}`;
    const props = [];
    if (f.o) props.push({ name: 'snif:apk-origin', value: f.o });
    if (f.c) props.push({ name: 'snif:aports-commit', value: f.c });
    const c = { 'bom-ref': purl, type: 'library', name: f.P, version: f.V, purl };
    if (props.length) c.properties = props;
    return c;
});
const pkgRef = (name) => (pkgs.find((c) => c.name === name) || {})['bom-ref'];
// snifd links these from the image (the Dockerfile builds it against them).
const links = ['musl', 'libssl3', 'libcrypto3', 'libcurl'];
for (const l of links) if (!pkgRef(l)) die(`no ${l} among the image's ${pkgs.length} packages`);

const imageRef = `pkg:oci/snif@${enc(digest)}?repository_url=${enc(repo)}&tag=${enc(version)}`;
const snifRef = `pkg:github/vesvault/snif@v${version}`;
const osRef = `os:${distro}`;
const supplier = { name: 'VESvault Corp', url: ['https://vesvault.com'] };
const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
        tools: { components: [{ type: 'application', name: 'snif docker/image-sbom.js',
            hashes: [{ alg: 'SHA-256', content: sha256(fs.readFileSync(__filename)) }] }] },
        component: {
            'bom-ref': imageRef, type: 'container', name: 'vesvault/snif', version, purl: imageRef, supplier,
            hashes: [{ alg: 'SHA-256', content: digest.replace(/^sha256:/, '') }],
            externalReferences: [
                { type: 'distribution', url: 'https://github.com/vesvault/snif/pkgs/container/snif', comment: `${repo}:${version}@${digest}` },
                { type: 'vcs', url: 'https://github.com/vesvault/snif' },
            ],
            properties: [
                { name: 'snif:revision', value: revision },
                { name: 'snif:base', value: osr.PRETTY_NAME || `Alpine ${osr.VERSION_ID}` },
            ].concat(plats.map((p) => ({ name: `snif:platform:${p.name}`, value: p.digest }))),
        },
    },
    components: [
        {
            'bom-ref': snifRef, type: 'application', name: 'snif', version, purl: snifRef, supplier,
            licenses: [{ license: { id: 'Apache-2.0' } }],
            externalReferences: [{ type: 'vcs', url: 'https://github.com/vesvault/snif' }],
            pedigree: { commits: [{ uid: revision, url: `https://github.com/vesvault/snif/commit/${revision}` }] },
            properties: [{ name: 'snif:path', value: '/usr/bin/snifd' }]
                .concat(plats.map((p) => ({ name: `snif:sha256:${p.name}`, value: p.snifd }))),
        },
        { 'bom-ref': osRef, type: 'operating-system', name: osr.ID, version: osr.VERSION_ID, description: osr.PRETTY_NAME },
    ].concat(pkgs),
    dependencies: [
        { ref: imageRef, dependsOn: [snifRef, osRef] },
        { ref: snifRef, dependsOn: links.map(pkgRef) },
        { ref: osRef, dependsOn: pkgs.map((c) => c['bom-ref']) },
    ],
};
const id = sha256(JSON.stringify(bom));
const uuid = `${id.slice(0, 8)}-${id.slice(8, 12)}-5${id.slice(13, 16)}-`
    + `${(8 | (parseInt(id[16], 16) & 3)).toString(16)}${id.slice(17, 20)}-${id.slice(20, 32)}`;
process.stdout.write(JSON.stringify(Object.assign({ bomFormat: bom.bomFormat, specVersion: bom.specVersion,
    serialNumber: `urn:uuid:${uuid}` }, bom), null, 2) + '\n');
process.stderr.write(`image-sbom: ${image} ${digest}: snif ${version} (${revision.slice(0, 7)}), `
    + `${plats.map((p) => p.name).join(' ')}, ${pkgs.length} packages of Alpine ${osr.VERSION_ID}\n`);
