import React from 'react';
import { Prism } from 'react-syntax-highlighter';
import * as themes from 'react-syntax-highlighter/dist/esm/styles/prism'

const text = 'rgb(78,253,120)';



const getLanguage = className => {
    const match = /language-(\w*)/.exec(className || 'language-javascript')
    let lang = 'javascript'
    if (match && match.length > 1) {
      lang = match[1]
    }
    return lang
  }

// const pre = props => props.children;
const code = props => {
    const language = getLanguage(props.className);
    return <Prism language={language} style={themes.twilight} {...props} />
}

export default {
    googleFont: 'https://fonts.googleapis.com/css?family=Source+Code+Pro',
    fonts: {
        body: '"Source Code Pro", monospace',
        monospace: '"Source Code Pro", monospace',
    },
    colors: {
        text,
        background: 'black',
        primary: 'white',
    },
    components: {
        // pre,
        code
    },
    styles: {
        // pre: {
        //     color: 'background',
        //     bg: 'text',
        // },
    },
}