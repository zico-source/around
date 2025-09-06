/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run "npm run dev" in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run "npm run deploy" to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export default {
  async fetch(request, env, ctx) {

    const upgradeHeader = request.headers.get('Upgrade');
    const url = new URL(request.url);
            
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
                
                const 路径 = url.pathname.toLowerCase();
                if (路径 == '/') {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    // else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response('Hello World!');
                } else if (路径 != '/') {
                    return new Response('Hello World! Path: ' + 路径);
                } else {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else return new Response('should not be here');
                }
            }

     return new Response(request.method + ' My World!');

  }
};