import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
const port=Number(process.env.DASHBOARD_PORT??4173), root=process.cwd();
const artifact=join(root,"artifacts","hunt","latest.json"), page=join(root,"dashboard","index.html");
createServer(async(req,res)=>{try{if(req.url?.startsWith("/api/hunt")){let body;try{body=await readFile(artifact,"utf8")}catch{body=JSON.stringify({programsDiscovered:0,scannedRepositories:0,candidateFindings:0,skippedRepositories:0,attemptedRepositories:0,rateLimited:false,results:[]})}res.writeHead(200,{"content-type":"application/json","cache-control":"no-store"});return res.end(body)}const body=await readFile(page,"utf8");res.writeHead(200,{"content-type":"text/html; charset=utf-8","cache-control":"no-store"});res.end(body)}catch{res.writeHead(404);res.end("Not found")}}).listen(port,()=>console.log(JSON.stringify({service:"onchain-hunter-dashboard",url:"http://localhost:"+port})));