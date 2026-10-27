// =============================
// ROTAS DE GESTÃO DO ERP (Configurações e Cadastros Base)
// =============================

// Estado em memória com sincronização ou fallback no Supabase
let configuracoesMemoria = { limiteJanela: 3, capacidadePatio: 15, bloqueio: false };

app.get('/api/configuracoes', autenticarToken, async (req, res) => {
  try {
    const { data } = await supabase.from('configuracoes').select('*').single();
    if (data) configuracoesMemoria = data;
    res.json(configuracoesMemoria);
  } catch (err) {
    res.json(configuracoesMemoria);
  }
});

app.put('/api/configuracoes', autenticarToken, somenteAdmin, async (req, res) => {
  try {
    const { limiteJanela, capacidadePatio, bloqueio } = req.body;
    configuracoesMemoria = { limiteJanela, capacidadePatio, bloqueio };
    
    await supabase.from('configuracoes').upsert([{ id: 1, ...configuracoesMemoria }]);
    await registrarLog(req.usuario.email, `Atualizou regras operacionais (Pátio: ${capacidadePatio}, Janela: ${limiteJanela})`);
    
    res.json(configuracoesMemoria);
  } catch (err) {
    res.json(configuracoesMemoria);
  }
});

app.get('/api/cadastros-base', autenticarToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('cadastros_base').select('*').order('nome');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/cadastros-base', autenticarToken, async (req, res) => {
  try {
    const { tipo, nome, documento } = req.body;
    if (!tipo || !nome) return res.status(400).json({ erro: 'Tipo e nome são obrigatórios.' });

    const { data, error } = await supabase.from('cadastros_base').insert([{ tipo, nome, documento }]).select().single();
    if (error) throw error;

    await registrarLog(req.usuario.email, `Cadastrou novo ${tipo}: ${nome}`);
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao salvar cadastro base.' });
  }
});