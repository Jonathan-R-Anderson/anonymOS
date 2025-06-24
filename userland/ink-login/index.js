const React = require('react');
const {render, Text, Box, useApp, useInput} = require('ink');

const expectedUser = 'wcuser';
const expectedPass = 'wcpass';

const Login = () => {
  const {exit} = useApp();
  const [stage, setStage] = React.useState('user');
  const [username, setUsername] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [message, setMessage] = React.useState('');

  useInput((input, key) => {
    if (stage === 'done') {
      if (key.return) exit();
      return;
    }
    if (key.return) {
      if (stage === 'user') {
        setStage('pass');
      } else if (stage === 'pass') {
        if (username === expectedUser && password === expectedPass) {
          setMessage('Login successful');
        } else {
          setMessage('Invalid credentials');
        }
        setStage('done');
      }
      return;
    }
    if (key.backspace || key.delete) {
      if (stage === 'user') setUsername(username.slice(0, -1));
      else if (stage === 'pass') setPassword(password.slice(0, -1));
      return;
    }
    if (stage === 'user') setUsername(username + input);
    else if (stage === 'pass') setPassword(password + input);
  });

  return (
    <Box flexDirection="column">
      <Text color="cyan">+-----------------------+</Text>
      <Text color="cyan">|     anonymOS Login    |</Text>
      <Text color="cyan">+-----------------------+</Text>
      {stage === 'user' && <Text>Username: {username}</Text>}
      {stage === 'pass' && <Text>Password: {'*'.repeat(password.length)}</Text>}
      {stage === 'done' && <Text>{message} (press Enter)</Text>}
    </Box>
  );
};

render(React.createElement(Login));
