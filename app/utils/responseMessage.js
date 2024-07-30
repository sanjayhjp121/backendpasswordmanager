const messages = {
    English: {
        IncorrectLogin: "Invalid login credentials.",
    }
};

const getMessage = (key, language) => {
    return messages[language]?.[key] || messages['English'][key];
};

module.exports = { getMessage };