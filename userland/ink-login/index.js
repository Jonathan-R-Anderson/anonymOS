import React from 'react';
import {render, Text, Box, useApp, useInput} from 'ink';

const expectedUser = 'wcuser';
const expectedPass = 'wcpass';

const Login = () => {
  const {exit} = useApp();
  const [stage, setStage] = React.useState('user');
  const [username, setUsername] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [message, setMessage] = React.useState('');
  const [success, setSuccess] = React.useState(false);

  useInput((input, key) => {
    if (stage === 'done') {
      if (key.return) {
        exit();
        process.exit(success ? 0 : 1);
      }
      return;
    }
    if (key.return) {
      if (stage === 'user') {
        setStage('pass');
      } else if (stage === 'pass') {
        if (username === expectedUser && password === expectedPass) {
          setMessage('Login successful');
          setSuccess(true);
        } else {
          setMessage('Invalid credentials');
          setSuccess(false);
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

  const header = process.env.INK_LOGIN_HEADER || 'anonymOS Login';
  const color = process.env.INK_LOGIN_COLOR || 'cyan';
  const border = '+-----------------------+';
  return React.createElement(
    Box,
    {flexDirection: 'column'},
    React.createElement(Text, {color}, border),
    React.createElement(Text, {color}, `|     ${header}    |`),
    React.createElement(Text, {color}, border),
    stage === 'user' && React.createElement(Text, null, `Username: ${username}`),
    stage === 'pass' &&
      React.createElement(
        Text,
        null,
        `Password: ${'*'.repeat(password.length)}`
      ),
    stage === 'done' &&
      React.createElement(Text, null, `${message} (press Enter)`)
  );
};

render(React.createElement(Login));
