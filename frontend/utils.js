function lerTokenSeguro(token) {
    if (!token) return null;
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (error) {
        console.error("Erro ao decodificar o token:", error);
        return null;
    }
}

// Função central de Fetch com tratamento automático de sessão expirada
async function fetchAutenticado(url, options = {}) {
    const token = localStorage.getItem('token');
    
    // Garante o cabeçalho de Autorização
    options.headers = {
        ...options.headers,
        'Authorization': `Bearer ${token}`
    };

    try {
        const response = await fetch(url, options);

        // Se o token expirou ou for inválido
        if (response.status === 401 || response.status === 403) {
            localStorage.clear();
            if (typeof Swal !== 'undefined') {
                await Swal.fire({
                    title: 'Sessão Expirada',
                    text: 'Sua sessão expirou por inatividade. Faça login novamente.',
                    icon: 'warning',
                    confirmButtonText: 'Ir para o Login'
                });
            } else {
                alert('Sua sessão expirou. Faça login novamente.');
            }
            window.location.href = 'login.html';
            return null;
        }

        return response;
    } catch (error) {
        console.error("Erro na requisição:", error);
        throw error;
    }
}

// Exemplo de chamada segura no erp.html usando a nova função centralizada
async function registrarPesagem(dadosPesagem) {
    const res = await fetchAutenticado(`${API}/api/pesagens`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(dadosPesagem)
    });

    if (!res || !res.ok) return;
    
    const resultado = await res.json();
    Swal.fire('Sucesso!', 'Pesagem registrada com sucesso.', 'success');
}