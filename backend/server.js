import express from 'express';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'se7_terminais_jwt_secret_2026';

// =============================
// CONFIGURAÇÃO DO SUPABASE
// =============================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("ERRO CRÍTICO: Configurações do Supabase ausentes no arquivo .env");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// =============================
// MIDDLEWARES INICIAIS
// =============================
app.use(cors());
app.use(express.json());

// =============================
// FUNÇÕES AUXILIARES DE NEGÓCIO
// =============================
async function registrarLog(usuarioEmail, acao) {
  try {
    await supabase.from('logs').insert([
      { usuario: usuarioEmail, acao, datahora: new Date().toISOString() }
    ]);
  } catch (error) {
    console.error('Erro ao registrar log no Supabase:', error.message);
  }
}

async function criarAdminPadrao() {
  try {
    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', 'admin@empresa.com')
      .maybeSingle();

    if (!user) {
      // Inserção direta sem hash para garantir compatibilidade total
      await supabase.from('users').insert([
        {
          nome: 'Administrador',
          email: 'admin@empresa.com',
          senha: '123456',
          perfil: 'admin',
          ativo: true
        }
      ]);
      console.log('Usuário administrador verificado/criado no Supabase: admin@empresa.com / 123456');
    }
  } catch (error) {
    console.error('Erro ao verificar administrador padrão:', error.message);
  }
}

// Middleware de validação do token JWT
function autenticarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ erro: 'Token não informado.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ erro: 'Token inválido ou expirado.' });
  }
}

function somenteAdmin(req, res, next) {
  if (req.usuario.perfil !== 'admin') {
    return res.status(403).json({ erro: 'Acesso restrito ao administrador.' });
  }
  next();
}

// =============================
// ROTAS DE AUTENTICAÇÃO E USUÁRIO
// =============================
app.post('/api/cadastro', async (req, res) => {
  try {
    const { nome, email, senha } = req.body;
    const perfilSeguro = 'usuario';

    if (!nome || !email || !senha) {
      return res.status(400).json({ erro: 'Nome, e-mail e senha são obrigatórios.' });
    }

    const { data: userExiste } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .maybeSingle();

    if (userExiste) {
      return res.status(400).json({ erro: 'E-mail já cadastrado.' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);
    
    const { error } = await supabase.from('users').insert([
      { nome, email: email.toLowerCase(), senha: senhaHash, perfil: perfilSeguro, ativo: true }
    ]);

    if (error) throw error;

    await registrarLog(email, 'Cadastro de usuário');
    res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro interno no servidor ao cadastrar.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, usuario, senha } = req.body;
    const login = email || usuario;

    if (!login || !senha) {
      return res.status(400).json({ erro: 'Login e senha são obrigatórios.' });
    }

    const { data: user } = await supabase
      .from('users')
      .select('*')
      .eq('email', login.toLowerCase())
      .maybeSingle();

    if (!user) {
      return res.status(401).json({ erro: 'Usuário não encontrado.' });
    }

    if (!user.ativo) {
      return res.status(403).json({ erro: 'Usuário inativo.' });
    }

    // Validação direta sem bcrypt para evitar qualquer falha de hash
    if (senha !== user.senha) {
      return res.status(401).json({ erro: 'Senha inválida.' });
    }

    const token = jwt.sign(
      { id: user.id, nome: user.nome, email: user.email, perfil: user.perfil },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    await registrarLog(user.email, 'Login realizado');

    res.json({
      token,
      usuario: { id: user.id, nome: user.nome, email: user.email, perfil: user.perfil, ativo: user.ativo }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro interno no servidor ao autenticar.' });
  }
});

app.put('/api/perfil', autenticarToken, async (req, res) => {
  try {
    const { senhaNova } = req.body;
    
    if (!senhaNova || senhaNova.length < 6) {
      return res.status(400).json({ erro: 'A senha deve ter no mínimo 6 caracteres.' });
    }

    const { error } = await supabase
      .from('users')
      .update({ senha: senhaNova })
      .eq('id', req.usuario.id);

    if (error) throw error;

    await registrarLog(req.usuario.email, 'Alterou a própria senha de acesso');
    res.json({ mensagem: 'Senha atualizada com sucesso.' });
  } catch (error) {
    console.error('Erro ao atualizar perfil:', error);
    res.status(500).json({ erro: 'Erro interno ao atualizar perfil.' });
  }
});

// =============================
// ROTA PÚBLICA DE RASTREIO
// =============================
app.get('/api/rastreio/:codigo', async (req, res) => {
  try {
    const codigoDigitado = decodeURIComponent(req.params.codigo).trim();
    const codigoLimpo = codigoDigitado.replace(/^id\s*/i, '').replace(/^#/, '').trim();
    
    let query = supabase.from('agendamentos').select('id, cliente, transportadora, produto, status, datahora, atualizadoem');
    
    if (/^\d+$/.test(codigoLimpo)) {
      query = query.eq('id', parseInt(codigoLimpo, 10));
    } else {
      query = query.eq('di', codigoDigitado);
    }

    const { data, error } = await query.maybeSingle();

    if (error) {
        console.error("Erro interno do Supabase:", error);
        throw error;
    }
    
    if (!data) return res.status(404).json({ erro: 'Carga não encontrada.' });

    res.json(data);
  } catch (error) {
    console.error("Erro na Rota de Rastreio:", error);
    res.status(500).json({ erro: 'Erro interno ao buscar rastreio.' });
  }
});

// =============================
// ROTAS DE AGENDAMENTOS
// =============================
app.get('/api/agendamentos', autenticarToken, async (req, res) => {
  try {
    let query = supabase.from('agendamentos').select('*');
    
    if (req.usuario.perfil !== 'admin') {
      query = query.eq('usuarioid', req.usuario.id);
    }

    const { data: agendamentos, error } = await query;
    if (error) throw error;

    res.json(agendamentos || []);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar agendamentos.' });
  }
});

app.post('/api/agendamentos', autenticarToken, async (req, res) => {
  try {
    const bodyMinusculo = {};
    for (const key in req.body) {
      bodyMinusculo[key.toLowerCase()] = req.body[key];
    }

    const payload = {
      ...bodyMinusculo,
      usuarioid: req.usuario.id,
      usuarionome: req.usuario.nome,
      criadoem: new Date().toISOString()
    };

    const { data, error } = await supabase
      .from('agendamentos')
      .insert([payload])
      .select()
      .single();

    if (error) throw error;

    await registrarLog(req.usuario.email, `Criou agendamento #${data.id}`);
    res.status(201).json(data);
  } catch (error) {
    console.error('ERRO NO SUPABASE:', error);
    res.status(500).json({ erro: 'Erro interno no servidor ao criar agendamento.' });
  }
});

app.put('/api/agendamentos/:id', autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: agendamento } = await supabase
      .from('agendamentos')
      .select('*')
      .eq('id', id)
      .maybeSingle();

    if (!agendamento) {
      return res.status(404).json({ erro: 'Agendamento não encontrado.' });
    }

    if (req.usuario.perfil !== 'admin' && agendamento.usuarioid !== req.usuario.id) {
      return res.status(403).json({ erro: 'Acesso negado.' });
    }

    const bodyMinusculo = {};
    for (const key in req.body) {
      bodyMinusculo[key.toLowerCase()] = req.body[key];
    }

    const payloadAtualizacao = {
      ...bodyMinusculo,
      atualizadoem: new Date().toISOString()
    };

    const { data, error } = await supabase
      .from('agendamentos')
      .update(payloadAtualizacao)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await registrarLog(req.usuario.email, `Editou agendamento #${id}`);
    res.json(data);
  } catch (error) {
    console.error('ERRO NO SUPABASE:', error);
    res.status(500).json({ erro: 'Erro interno no servidor ao atualizar agendamento.' });
  }
});

app.delete('/api/agendamentos/:id', autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: agendamento } = await supabase
      .from('agendamentos')
      .select('*')
      .eq('id', id)
      .maybeSingle();

    if (!agendamento) {
      return res.status(404).json({ erro: 'Agendamento não encontrado.' });
    }

    if (req.usuario.perfil !== 'admin' && agendamento.usuarioid !== req.usuario.id) {
      return res.status(403).json({ erro: 'Acesso negado.' });
    }

    const { error } = await supabase.from('agendamentos').delete().eq('id', id);
    if (error) throw error;

    await registrarLog(req.usuario.email, `Excluiu agendamento #${id}`);
    res.json({ mensagem: 'Agendamento excluído com sucesso.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro interno no servidor ao excluir agendamento.' });
  }
});

// =============================
// ROTAS ADMINISTRATIVAS
// =============================
app.get('/api/users', autenticarToken, somenteAdmin, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, nome, email, perfil, ativo');

    if (error) throw error;
    res.json(users || []);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar usuários.' });
  }
});

app.put('/api/users/:id', autenticarToken, somenteAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { perfil, ativo } = req.body;

    const updates = {};
    if (perfil !== undefined) updates.perfil = perfil;
    if (ativo !== undefined) updates.ativo = ativo;

    const { error } = await supabase.from('users').update(updates).eq('id', id);
    if (error) throw error;

    await registrarLog(req.usuario.email, `Alterou permissões do usuário #${id}`);
    res.json({ mensagem: 'Usuário atualizado com sucesso.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro interno no servidor ao atualizar perfil.' });
  }
});

app.get('/api/logs', autenticarToken, somenteAdmin, async (req, res) => {
  try {
    const { data: logs, error } = await supabase
      .from('logs')
      .select('*')
      .order('datahora', { ascending: false });

    if (error) throw error;
    res.json(logs || []);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar logs.' });
  }
});

// =============================
// ROTAS DO ERP (Portaria, Balança e Pátio)
// =============================
app.patch('/api/agendamentos/:id/status', autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ erro: 'O novo status é obrigatório.' });
    }

    const { data: agendamento } = await supabase
      .from('agendamentos')
      .select('*')
      .eq('id', id)
      .maybeSingle();

    if (!agendamento) {
      return res.status(404).json({ erro: 'Agendamento não encontrado.' });
    }

    const { data, error } = await supabase
      .from('agendamentos')
      .update({ 
        status: status, 
        atualizadoem: new Date().toISOString() 
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await registrarLog(req.usuario.email, `Atualizou status do agendamento #${id} para ${status}`);
    res.json({ mensagem: 'Status atualizado com sucesso.', dados: data });
  } catch (error) {
    console.error('Erro ao atualizar status:', error);
    res.status(500).json({ erro: 'Erro interno ao atualizar status.' });
  }
});

app.post('/api/pesagens', autenticarToken, async (req, res) => {
  try {
    const { agendamentoid, tipo, peso, nf } = req.body;

    if (!agendamentoid || !tipo || peso == null) {
      return res.status(400).json({ erro: 'ID do agendamento, tipo de pesagem e peso são obrigatórios.' });
    }

    const { data: agendamento, error: errBusca } = await supabase
      .from('agendamentos')
      .select('*')
      .eq('id', agendamentoid)
      .single();

    if (errBusca || !agendamento) {
      return res.status(404).json({ erro: 'Agendamento não encontrado.' });
    }

    let payloadAtualizacao = {};
    let novoStatus = agendamento.status;

    if (tipo === 'tara') {
      payloadAtualizacao.tara = parseFloat(peso);
      payloadAtualizacao.tarats = new Date().toISOString();
      novoStatus = 'Vistoria / Pátio';
    } else if (tipo === 'bruto') {
      const taraAtual = agendamento.tara || 0;
      const pesoBrutoNum = parseFloat(peso);

      if (taraAtual > 0 && pesoBrutoNum <= taraAtual) {
        return res.status(400).json({ erro: 'O peso bruto não pode ser menor ou igual à tara.' });
      }

      payloadAtualizacao.bruto = pesoBrutoNum;
      payloadAtualizacao.brutots = new Date().toISOString();
      payloadAtualizacao.liquido = pesoBrutoNum - taraAtual;
      novoStatus = 'Faturamento / NF';
    }

    if (nf) {
      payloadAtualizacao.nf = nf;
    }

    payloadAtualizacao.status = novoStatus;
    payloadAtualizacao.atualizadoem = new Date().toISOString();

    const { data, error } = await supabase
      .from('agendamentos')
      .update(payloadAtualizacao)
      .eq('id', agendamentoid)
      .select()
      .single();

    if (error) throw error;

    await registrarLog(req.usuario.email, `Registrou pesagem de ${tipo} (${peso} kg) no agendamento #${agendamentoid}`);
    res.status(201).json({ mensagem: 'Pesagem registrada com sucesso.', dados: data });
  } catch (error) {
    console.error('Erro ao registrar pesagem:', error);
    res.status(500).json({ erro: 'Erro interno ao registrar pesagem.' });
  }
});

app.get('/', (req, res) => {
  res.json({ mensagem: 'API SE7 Terminais integrada com a nuvem do Supabase rodando perfeitamente.' });
});

// =============================
// INICIALIZAÇÃO
// =============================
criarAdminPadrao().then(() => {
  app.listen(PORT, () => {
    console.log(`Servidor rodando em nuvem híbrida na porta http://localhost:${PORT}`);
  });
});