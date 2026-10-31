export default function Home() {
  return (
    <main className="mx-auto w-full max-w-3xl p-8 font-sans">
      <h1 className="text-2xl font-semibold">The Possessed Butler</h1>
      <p className="mt-4 text-sm opacity-80">
        The agent core runs in tests with a mock provider. The chat, approval and audit UI
        will be connected once the security engine is available to wire into the API routes.
      </p>
    </main>
  );
}
