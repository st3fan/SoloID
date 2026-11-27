import { fixture } from '../test/helpers.js';

// For isolated tests only. Passwords are deliberately public test credentials.
const runtime = await fixture();
runtime.config.issuer = process.env.TEST_ISSUER ?? 'http://localhost:3000';
console.log(JSON.stringify(runtime.config, null, 2));
