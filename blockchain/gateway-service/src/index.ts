import express, { NextFunction, Request, Response } from 'express';
import { FabricConnection, loadConfigFromEnv } from './fabricClient';

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.PORT || 4001);

let connection: FabricConnection | null = null;
let connectionError: string | null = null;

function getConnection(): FabricConnection {
    if (connection) {
        return connection;
    }
    const config = loadConfigFromEnv();
    connection = new FabricConnection(config);
    return connection;
}

app.get('/health', (_req: Request, res: Response) => {
    try {
        getConnection();
        res.json({ status: 'ok', connected: true });
    } catch (err) {
        connectionError = err instanceof Error ? err.message : String(err);
        res.status(503).json({ status: 'unavailable', connected: false, error: connectionError });
    }
});

interface InvokePayload {
    channel: string;
    chaincode: string;
    function: string;
    args: string[];
}

app.post('/invoke', async (req: Request<unknown, unknown, InvokePayload>, res: Response) => {
    try {
        const { function: fn, args } = req.body;
        const conn = getConnection();
        const { transactionId, result } = await conn.invoke(fn, args || []);
        let parsedResult: unknown = result;
        try {
            parsedResult = JSON.parse(result);
        } catch {
            // non-JSON return value -- pass through as raw string
        }
        res.json({ transactionId, blockNumber: null, result: parsedResult });
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : String(err) });
    }
});

app.post('/query', async (req: Request<unknown, unknown, InvokePayload>, res: Response) => {
    try {
        const { function: fn, args } = req.body;
        const conn = getConnection();
        const result = await conn.query(fn, args || []);
        let parsedResult: unknown = result;
        try {
            parsedResult = JSON.parse(result);
        } catch {
            // non-JSON return value
        }
        // Chaincode read functions in this contract return {"record": ...}
        // shaped JSON directly -- pass it through so the FastAPI verifier
        // can read `.record` uniformly.
        if (parsedResult && typeof parsedResult === 'object') {
            res.json(parsedResult);
        } else {
            res.json({ result: parsedResult });
        }
    } catch (err) {
        res.status(502).json({ error: err instanceof Error ? err.message : String(err) });
    }
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    res.status(500).json({ error: err.message });
});

app.listen(PORT, () => {
    console.log(`Fabric gateway sidecar listening on port ${PORT}`);
});
