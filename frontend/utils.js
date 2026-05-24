function lerTokenSeguro(token) {
    if (!token) return null;
    try {
        const base64Url = token.split('.')[1];
        // O replace corrige caracteres de URL para o formato Base64 padrão
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        // O map traduz perfeitamente qualquer acento (UTF-8)
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (error) {
        console.error("Erro ao decodificar o token:", error);
        return null;
    }
}