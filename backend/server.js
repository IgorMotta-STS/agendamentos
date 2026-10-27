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
if (!process.env.JWT_SECRET) {
  console.warn('AVISO: JWT_SECRET não definido no .env; usando valor padrão (inseguro em produção).');
}

const STATUS_VALIDOS = ['Agendado', 'Em andamento', 'Finalizado'];
const CAMPOS_PROTEGIDOS = ['id', 'usuarioid', 'usuarionome', 'criadoem', 'tara', 'tarats', 'bruto', 'brutots', 'liquido'];

const ehHashBcrypt = (valor) => typeof valor === 'string' && /^\$2[aby]\$\d{2}\$/.test(valor);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("ERRO CRÍTICO: Configurações do Supabase ausentes no arquivo .env");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

app.use(cors());
app.use(express.json());

// =============================
// FUNÇÕES AUXILIARES DE NEGÓCIO
// =============================
async function registrarLog(nomeOperador, acao) {
  try {
    await supabase.from('logs').insert([
      { usuario: nomeOperador || 'Sistema', acao, datahora: new Date().toISOString() }
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
      const senhaHash = await bcrypt.hash('123456', 10);
      await supabase.from('users').insert([
        {
          nome: 'Administrador',
          email: 'admin@empresa.com',
          senha: senhaHash,
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

    await registrarLog(nome, 'Cadastro de usuário');
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

    let senhaOk = false;
    if (ehHashBcrypt(user.senha)) {
      senhaOk = await bcrypt.compare(senha, user.senha);
    } else if (senha === user.senha) {
      senhaOk = true;
      const novoHash = await bcrypt.hash(senha, 10);
      await supabase.from('users').update({ senha: novoHash }).eq('id', user.id);
    }

    if (!senhaOk) {
      return res.status(401).json({ erro: 'Senha inválida.' });
    }

    const token = jwt.sign(
      { id: user.id, nome: user.nome, email: user.email, perfil: user.perfil },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    await registrarLog(user.nome, 'Login realizado');

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

    const senhaHash = await bcrypt.hash(senhaNova, 10);
    const { error } = await supabase
      .from('users')
      .update({ senha: senhaHash })
      .eq('id', req.usuario.id);

    if (error) throw error;

    await registrarLog(req.usuario.nome, 'Alterou a própria senha de acesso');
    res.json({ mensagem: 'Senha atualizada com sucesso.' });
  } catch (error) {
    console.error('Erro ao atualizar perfil:', error);
    res.status(500).json({ erro: 'Erro interno ao atualizar perfil.' });
  }
});

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

    if (error) throw error;
    if (!data) return res.status(404).json({ erro: 'Carga não encontrada.' });

    res.json(data);
  } catch (error) {
    res.status(500).json({ erro: 'Erro interno ao buscar rastreio.' });
  }
});

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
      const campo = key.toLowerCase();
      if (!CAMPOS_PROTEGIDOS.includes(campo)) bodyMinusculo[campo] = req.body[key];
    }

    const payload = {
      ...bodyMinusculo,
      status: STATUS_VALIDOS.includes(bodyMinusculo.status) ? bodyMinusculo.status : 'Agendado',
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

    await registrarLog(req.usuario.nome, `Criou agendamento #${data.id}`);
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ erro: 'Erro interno no servidor ao criar agendamento.' });
  }
});

app.put('/api/agendamentos/:id', autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: agendamento } = await supabase.from('agendamentos').select('*').eq('id', id).maybeSingle();

    if (!agendamento) return res.status(404).json({ erro: 'Agendamento não encontrado.' });
    if (req.usuario.perfil !== 'admin' && agendamento.usuarioid !== req.usuario.id) {
      return res.status(403).json({ erro: 'Acesso negado.' });
    }

    const bodyMinusculo = {};
    for (const key in req.body) {
      const campo = key.toLowerCase();
      if (!CAMPOS_PROTEGIDOS.includes(campo)) bodyMinusculo[campo] = req.body[key];
    }

    if (bodyMinusculo.status !== undefined && !STATUS_VALIDOS.includes(bodyMinusculo.status)) {
      return res.status(400).json({ erro: 'Status inválido.' });
    }

    const payloadAtualizacao = { ...bodyMinusculo, atualizadoem: new Date().toISOString() };
    const { data, error } = await supabase.from('agendamentos').update(payloadAtualizacao).eq('id', id).select().single();

    if (error) throw error;

    await registrarLog(req.usuario.nome, `Editou agendamento #${id}`);
    res.json(data);
  } catch (error) {
    res.status(500).json({ erro: 'Erro interno no servidor ao atualizar agendamento.' });
  }
});

app.delete('/api/agendamentos/:id', autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: agendamento } = await supabase.from('agendamentos').select('*').eq('id', id).maybeSingle();

    if (!agendamento) return res.status(404).json({ erro: 'Agendamento não encontrado.' });
    if (req.usuario.perfil !== 'admin' && agendamento.usuarioid !== req.usuario.id) {
      return res.status(403).json({ erro: 'Acesso negado.' });
    }

    const { error } = await supabase.from('agendamentos').delete().eq('id', id);
    if (error) throw error;

    await registrarLog(req.usuario.nome, `Excluiu agendamento #${id}`);
    res.json({ mensagem: 'Agendamento excluído com sucesso.' });
  } catch (error) {
    res.status(500).json({ erro: 'Erro interno no servidor ao excluir agendamento.' });
  }
});

app.get('/api/users', autenticarToken, somenteAdmin, async (req, res) => {
  try {
    const { data: users, error } = await supabase.from('users').select('id, nome, email, perfil, ativo');
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

    await registrarLog(req.usuario.nome, `Alterou permissões do usuário #${id}`);
    res.json({ mensagem: 'Usuário atualizado com sucesso.' });
  } catch (error) {
    res.status(500).json({ erro: 'Erro interno no servidor ao atualizar perfil.' });
  }
});

app.get('/api/logs', autenticarToken, somenteAdmin, async (req, res) => {
  try {
    const { data: logs, error } = await supabase.from('logs').select('*').order('datahora', { ascending: false });
    if (error) throw error;
    res.json(logs || []);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar logs.' });
  }
});

app.patch('/api/agendamentos/:id/status', autenticarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, nf } = req.body;

    if (!status || !STATUS_VALIDOS.includes(status)) {
      return res.status(400).json({ erro: `Status inválido. Use: ${STATUS_VALIDOS.join(', ')}.` });
    }

    const { data: agendamento } = await supabase.from('agendamentos').select('*').eq('id', id).maybeSingle();
    if (!agendamento) return res.status(404).json({ erro: 'Agendamento não encontrado.' });

    const atual = agendamento.status || 'Agendado';
    const nfInformada = typeof nf === 'string' ? nf.trim() : '';
    const atualizacao = { status, atualizadoem: new Date().toISOString() };

    if (status === 'Em andamento') {
      if (atual === 'Finalizado') return res.status(400).json({ erro: 'Esta carga já foi finalizada.' });
      if (nfInformada) {
        if (!agendamento.bruto) return res.status(400).json({ erro: 'Registre a pesagem final (bruto) antes de informar a NF.' });
        atualizacao.nf = nfInformada;
      }
    } else if (status === 'Finalizado') {
      if (atual !== 'Em andamento') return res.status(400).json({ erro: 'Só é possível finalizar cargas que estão no pátio.' });
      if (!agendamento.tara || !agendamento.bruto) return res.status(400).json({ erro: 'A carga precisa das duas pesagens antes da saída.' });
      const nfFinal = nfInformada || agendamento.nf;
      if (!nfFinal) return res.status(400).json({ erro: 'Informe a nota fiscal antes de liberar a saída.' });
      atualizacao.nf = nfFinal;
    }

    const { data, error } = await supabase.from('agendamentos').update(atualizacao).eq('id', id).select().single();
    if (error) throw error;

    const detalhe = atualizacao.nf && status !== 'Finalizado' ? ` (NF ${atualizacao.nf})` : '';
    await registrarLog(req.usuario.nome, `Atualizou status do agendamento #${id} para ${status}${detalhe}`);
    res.json({ mensagem: 'Status atualizado com sucesso.', dados: data });
  } catch (error) {
    res.status(500).json({ erro: 'Erro interno ao atualizar status.' });
  }
});

app.post('/api/pesagens', autenticarToken, async (req, res) => {
  try {
    const { agendamentoid, tipo, peso } = req.body;
    const pesoNum = Number(peso);

    if (!agendamentoid || !['tara', 'bruto'].includes(tipo)) {
      return res.status(400).json({ erro: 'Informe o agendamento e o tipo de pesagem.' });
    }
    if (!Number.isFinite(pesoNum) || pesoNum <= 0 || pesoNum > 100000) {
      return res.status(400).json({ erro: 'Peso inválido.' });
    }

    const { data: agendamento } = await supabase.from('agendamentos').select('*').eq('id', agendamentoid).maybeSingle();
    if (!agendamento) return res.status(404).json({ erro: 'Agendamento não encontrado.' });
    if (agendamento.status !== 'Em andamento') return res.status(400).json({ erro: 'Veículo precisa estar no pátio.' });

    const agora = new Date().toISOString();
    const atualizacao = { atualizadoem: agora };

    if (tipo === 'tara') {
      if (agendamento.bruto) return res.status(400).json({ erro: 'A pesagem final já foi registrada.' });
      atualizacao.tara = pesoNum;
      atualizacao.tarats = agora;
    } else {
      const tara = Number(agendamento.tara) || 0;
      if (tara <= 0) return res.status(400).json({ erro: 'Registre a tara antes do bruto.' });
      if (pesoNum <= tara) return res.status(400).json({ erro: 'O peso bruto não pode ser menor ou igual à tara.' });
      atualizacao.bruto = pesoNum;
      atualizacao.brutots = agora;
      atualizacao.liquido = pesoNum - tara;
    }

    const { data, error } = await supabase.from('agendamentos').update(atualizacao).eq('id', agendamentoid).select().single();
    if (error) throw error;

    await registrarLog(req.usuario.nome, `Registrou pesagem de ${tipo} (${pesoNum} kg) no agendamento #${agendamentoid}`);
    res.status(201).json({ mensagem: 'Pesagem registrada com sucesso.', dados: data });
  } catch (error) {
    res.status(500).json({ erro: 'Erro interno ao registrar pesagem.' });
  }
});

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
    await registrarLog(req.usuario.nome, `Atualizou regras operacionais (Pátio: ${capacidadePatio}, Janela: ${limiteJanela})`);
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

    await registrarLog(req.usuario.nome, `Cadastrou novo ${tipo}: ${nome}`);
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao salvar cadastro base.' });
  }
});

app.get('/', (req, res) => {
  res.json({ mensagem: 'API SE7 Terminais integrada com a nuvem do Supabase rodando perfeitamente.' });
});

criarAdminPadrao().then(() => {
  app.listen(PORT, () => {
    console.log(`Servidor rodando em nuvem híbrida na porta http://localhost:${PORT}`);
  });
});