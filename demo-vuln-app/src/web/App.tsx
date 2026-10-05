// NSAT Demo Vulnerable Application — React TypeScript Component
// This file intentionally contains security vulnerabilities for NSAT demo purposes.
// DO NOT use in production.

import React, { useState } from "react";

// NSAT-TARGET: Hardcoded API key committed to source
const API_KEY = "sk-proj-AKIAIOSFODNN7EXAMPLE1234567890abcdef";
const API_BASE = "https://api.internal.example.com";

// NSAT-TARGET: eval() usage with user-controlled input
function executeFormula(input: string): number {
    // VULN: eval with untrusted user input — arbitrary JS execution
    return eval(input);
}

// NSAT-TARGET: dangerouslySetInnerHTML with unescaped user content (XSS)
interface CommentProps {
    content: string;
}

const Comment: React.FC<CommentProps> = ({ content }) => {
    return (
        // VULN: Direct XSS — user content injected into DOM without sanitization
        <div dangerouslySetInnerHTML={{ __html: content }} />
    );
};

// NSAT-TARGET: Wildcard CORS with credentials
async function fetchUserData(userId: string) {
    const response = await fetch(`${API_BASE}/users/${userId}`, {
        method: "GET",
        // VULN: credentials: 'include' with wildcard CORS origin = credential theft
        credentials: "include",
        headers: {
            "Authorization": `Bearer ${API_KEY}`,
        },
    });
    return response.json();
}

export { executeFormula, Comment, fetchUserData };
