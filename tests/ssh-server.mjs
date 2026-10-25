// Minimal SSH server used by the end-to-end test. Implements password auth,
// an interactive line-buffered shell and the /proc reads the monitor polls.
import pkg from 'ssh2';

const { Server, utils } = pkg;

const FILES = ['notes.txt', 'deploy.sh', 'logs'];

function runShell(cmd) {
    if (!cmd) return '';
    if (cmd === 'ls') return FILES.join('  ') + '\n';
    if (cmd === 'pwd') return '/home/demo\n';
    if (cmd.startsWith('echo ')) return cmd.slice(5) + '\n';
    if (cmd === 'uname -a') return 'Linux test-box 6.1.0-test #1 SMP x86_64 GNU/Linux\n';
    return 'bash: ' + cmd.split(/\s+/)[0] + ': command not found\n';
}

let cpuTick = 1000;
let netTick = 104857600;
let upTick = 93784.55;

function runExec(command) {
    if (command.includes('/proc/stat')) {
        // burn a growing amount of non-idle time so the CPU% delta is non-zero
        cpuTick += 400;
        netTick += 196608; // ~192 KiB between samples -> visible rate
        upTick += 3;
        const idle = 8000;
        return (
            '@@CPU 100 0 ' + cpuTick + ' ' + idle + ' 0 0 0 0\n' +
            '@@MEM 3938984 2411724 0 0\n' +
            '@@NET ' + netTick + ' ' + Math.round(netTick / 2) + '\n' +
            '@@LOAD 0.42 0.31 0.22 1/123 4567\n' +
            '@@UP ' + upTick.toFixed(2) + ' 1234567.89\n' +
            '@@WHO 2\n'
        );
    }
    if (command.includes('uname -s')) {
        return (
            'Linux\n' +
            '6.1.0-test\n' +
            'x86_64\n' +
            'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n' +
            'VERSION_ID="12"\n'
        );
    }
    return '';
}

export function startServer(port) {
    return new Promise((resolve, reject) => {
        const hostKey = utils.generateKeyPairSync('ed25519').private;
        const server = new Server({ hostKeys: [hostKey] }, (client) => {
            client.on('authentication', (ctx) => {
                if (ctx.method === 'password' && ctx.username === 'demo' && ctx.password === 'demo1234') ctx.accept();
                else ctx.reject(['password']);
            });
            client.on('ready', () => {
                client.on('session', (accept) => {
                    const session = accept();
                    session.on('pty', (a) => a && a());
                    session.on('window-change', (a) => a && a());
                    session.on('shell', (accept) => {
                        const stream = accept();
                        stream.write('Welcome to test-box\r\n$ ');
                        let buf = '';
                        stream.on('data', (chunk) => {
                            const text = chunk.toString('utf8');
                            for (const ch of text) {
                                if (ch === '\r' || ch === '\n') {
                                    stream.write('\r\n');
                                    const cmd = buf.trim();
                                    buf = '';
                                    if (cmd === 'exit') {
                                        stream.exit(0);
                                        stream.end();
                                        return;
                                    }
                                    const out = runShell(cmd);
                                    if (out) stream.write(out.replace(/\n/g, '\r\n'));
                                    stream.write('$ ');
                                } else if (ch === '\x7f' || ch === '\b') {
                                    if (buf) {
                                        buf = buf.slice(0, -1);
                                        stream.write('\b \b');
                                    }
                                } else if (ch === '\x03') {
                                    buf = '';
                                    stream.write('^C\r\n$ ');
                                } else if (ch >= ' ') {
                                    buf += ch;
                                    stream.write(ch);
                                }
                            }
                        });
                    });
                    session.on('exec', (accept, reject, info) => {
                        const stream = accept();
                        const out = runExec(info.command || '');
                        if (out) stream.write(out);
                        stream.exit(0);
                        stream.end();
                    });
                });
            });
            client.on('error', () => {});
        });
        server.on('error', reject);
        server.listen(port, '127.0.0.1', () => resolve({ server, port: server.address().port }));
    });
}

// Allow `node tests/ssh-server.mjs` for manual poking.
if (import.meta.url === 'file://' + process.argv[1]) {
    const port = Number(process.argv[2]) || 2222;
    startServer(port).then(({ port: p }) => console.log('test ssh server on 127.0.0.1:' + p));
}
