#!/usr/bin/env node
import { main } from '../src/client.mjs';
await main(process.argv.slice(2));
