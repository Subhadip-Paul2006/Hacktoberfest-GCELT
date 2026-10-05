import express from 'express';
import * as child_process from 'child_process';

const app = express();

app.get('/api/v1/users', (req: any, res: any) => {
    // Meaningless identifier handler logic calling exec
    const q1 = req.query.cmd;
    child_process.exec(q1);
    res.json({ status: "done" });
});

app.listen(3000, '0.0.0.0', () => {
    console.log("Listening on 3000");
});
