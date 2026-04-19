import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// This value should be shared between the OpenAuth server Worker and other
// client Workers that you connect to it, so the types and schema validation are
// consistent.
const subjects = createSubjects({
    user: object({
        id: string(),
    }),
});

// 1. UI anpassen: Texte für Registrierung und Passwort-Reset durch Leerzeichen verstecken
const myPasswordUI = PasswordUI({
    sendCode: async (email, code) => {
        // This is where you would email the verification code to the user
        console.log(`Sending code ${code} to ${email}`);
    },
    copy: {
        input_code: "Code (check Worker logs)",
        register_prompt: " ", 
        register: " ",
        change_prompt: " ",
    },
});

export default {
    fetch(request: Request, env: Env, ctx: ExecutionContext) {
        // This top section is just for demo purposes. 
        const url = new URL(request.url);
        if (url.pathname === "/") {
            url.searchParams.set("redirect_uri", url.origin + "/callback");
            url.searchParams.set("client_id", "your-client-id");
            url.searchParams.set("response_type", "code");
            url.pathname = "/authorize";
            return Response.redirect(url.toString());
        } else if (url.pathname === "/callback") {
            return Response.json({
                message: "OAuth flow complete!",
                params: Object.fromEntries(url.searchParams.entries()),
            });
        }

        // The real OpenAuth server code starts here:
        return issuer({
            storage: CloudflareStorage({
                namespace: env.AUTH_STORAGE,
            }),
            subjects,
            providers: {
                // 2. Modifizierte UI laden und Backend-Routen hart blockieren
                password: PasswordProvider({
                    ...myPasswordUI,
                    register: async () => new Response("Registrierung ist auf der Labs-Seite deaktiviert. Falls du Zugriff benötigst, wende dich an Fynn.", { status: 403 }),
                    change: async () => new Response("Passwort ändern deaktiviert. Bitte an Admin wenden.", { status: 403 }),
                }),
            },
            theme: {
                title: "Fynnlabs Auth-Service",
                primary: "#0051c3",
                favicon: 'https://fynnlabs.ch/img/fynnlabs_favicon.png',
                logo: {
                    dark: 'https://fynnlabs.ch/img/fynnlabs_favicon.png',
                    light: 'https://fynnlabs.ch/img/fynnlabs_favicon.png',
                },
                // HIER IST DAS CSS FÜR DEIN GRÖSSERES LOGO
                css: `
                    img {
                        height: 100px !important; 
                        max-height: none !important;
                        width: auto !important;
                    }
                `
            },
            success: async (ctx, value) => {
                return ctx.subject("user", {
                    // 3. Nur noch existierende User abfragen!
                    id: await getUserOnly(env, value.email),
                });
            },
        }).fetch(request, env, ctx);
    },
} satisfies ExportedHandler<Env>;

// 4. DATENBANK ABSICHERN: Reiner SELECT, kein automatisches Konto-Erstellen mehr
async function getUserOnly(env: Env, email: string): Promise<string> {
    const result = await env.AUTH_DB.prepare(
        `SELECT id FROM user WHERE email = ?`
    )
        .bind(email)
        .first<{ id: string }>();

    if (!result) {
        // Schmeißt einen Error, wenn jemand versucht sich einzuloggen, der nicht in der DB steht
        throw new Error(`Zugriff verweigert: E-Mail ${email} ist nicht für die Labs-Umgebung freigeschaltet. Melde dich bei Fynn, um Zugriff zu erhalten.`);
    }
    
    console.log(`Erfolgreicher Login für User ${result.id} mit E-Mail ${email}`);
    return result.id;
}