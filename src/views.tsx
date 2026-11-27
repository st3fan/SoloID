import type { Child } from 'hono/jsx';

function Layout({ title, children }: { title: string; children: Child }) {
  return <html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title} · SoloID</title><link rel="stylesheet" href="/app.css" /></head>
    <body class="min-h-dvh bg-stone-100 text-stone-900 antialiased">
      <div class="mx-auto flex min-h-dvh max-w-5xl flex-col px-6">
        <header class="flex items-center justify-between border-b border-stone-200 py-7">
          <a href="/" class="flex items-center gap-2.5 text-xl font-semibold tracking-tight" aria-label="SoloID home">
            <span class="flex size-8 items-center justify-center rounded-lg bg-stone-900 text-sm text-white" aria-hidden="true">S</span>SoloID
          </a><span class="text-xs tracking-wide text-stone-500">YOUR IDENTITY. YOUR SERVER.</span>
        </header>
        <main class="flex flex-1 items-center justify-center py-12"><div class="w-full max-w-md">{children}</div></main>
        <footer class="flex justify-between gap-3 border-t border-stone-200 py-6 text-xs text-stone-500"><span>Simple, private sign-in.</span><span>Powered by SoloID</span></footer>
      </div>
    </body></html>;
}

const inputClass = 'mt-2 block w-full rounded-lg border border-stone-300 bg-white px-3.5 py-3 text-base shadow-xs outline-none transition focus:border-emerald-700 focus:ring-2 focus:ring-emerald-700/20';
const buttonClass = 'w-full rounded-lg bg-stone-900 px-4 py-3 text-sm font-medium text-white transition hover:bg-stone-700 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-emerald-700';
const cardClass = 'rounded-2xl border border-stone-200 bg-white p-7 shadow-sm sm:p-9';

export function LoginPage({ app, csrf, email = '', error }: { app: string; csrf: string; email?: string; error?: string }) {
  return <Layout title="Sign in">
    <div class="mb-6 text-center text-xs font-medium uppercase tracking-widest text-emerald-800">One account. Your apps.</div>
    <section class={cardClass} aria-labelledby="heading">
      <h1 id="heading" class="text-2xl font-semibold tracking-tight">Welcome back</h1>
      <p class="mt-2 text-sm leading-6 text-stone-500">Sign in to continue to <strong class="font-medium text-stone-900">{app}</strong>.</p>
      {error && <div role="alert" class="mt-6 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-800">{error}</div>}
      <form method="post" action="/login" class="mt-7 space-y-5">
        <input type="hidden" name="csrf" value={csrf} />
        <div><label for="email" class="text-sm font-medium">Email address</label>
          <input class={inputClass} id="email" type="email" name="email" value={email} autocomplete="username" placeholder="you@example.com" maxlength={254} required /></div>
        <div><label for="password" class="text-sm font-medium">Password</label>
          <input class={inputClass} id="password" type="password" name="password" autocomplete="current-password" maxlength={1024} required /></div>
        <button type="submit" class={buttonClass}>Sign in <span aria-hidden="true" class="ml-1">→</span></button>
      </form>
    </section>
    <p class="mt-6 text-center text-xs leading-5 text-stone-500">Your account is managed by your server administrator.</p>
  </Layout>;
}

export function MessagePage({ title, message }: { title: string; message: string }) {
  return <Layout title={title}><section class={cardClass}><h1 class="text-2xl font-semibold tracking-tight">{title}</h1>
    <p class="mt-3 text-sm leading-6 text-stone-500">{message}</p></section></Layout>;
}

export function LogoutPage({ csrf }: { csrf: string }) {
  return <Layout title="Sign out"><section class={cardClass}><h1 class="text-2xl font-semibold tracking-tight">Sign out of SoloID?</h1>
    <p class="mt-3 text-sm leading-6 text-stone-500">This ends your sign-in session here. Apps you already signed in to may keep their own sessions.</p>
    <form method="post" action="/logout" class="mt-7"><input type="hidden" name="csrf" value={csrf} /><button class={buttonClass}>Sign out</button></form>
  </section></Layout>;
}
