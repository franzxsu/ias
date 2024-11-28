console.log("gasdasda")

document.addEventListener('DOMContentLoaded', function () {
    const encryptionDropdownItems = document.querySelectorAll('#encryptionDropdown .dropdown-item');
    const decryptionDropdownItems = document.querySelectorAll('#decryptionDropdown .dropdown-item');
    const encryptionDropdownToggle = document.querySelector('#dropdownEncryptBtn');
    const decryptionDropdownToggle = document.querySelector('#dropdownDecryptBtn');
    const encryptionHiddenInput = document.getElementById('encryptionType');
    const decryptionHiddenInput = document.getElementById('decryptionType');

    encryptionDropdownItems.forEach(item => {
        item.addEventListener('click', function () {
            encryptionDropdownToggle.textContent = this.textContent.trim();
            console.log("ENCRYPTION DROPDOWN: "+this.getAttribute('data-value'));
            encryptionHiddenInput.value = this.getAttribute('data-value');
        });
    });

    decryptionDropdownItems.forEach(item => {
        item.addEventListener('click', function () {
            decryptionDropdownToggle.textContent = this.textContent.trim();
            console.log("DECRYPTION DROPDOWN: "+this.getAttribute('data-value'));
            decryptionHiddenInput.value = this.getAttribute('data-value');
        });
    });

    //ENCRYPTION FORM
    const encryptionForm = document.querySelector('form[action="/encrypt"]');
    encryptionForm.addEventListener('submit', function (e) {
        e.preventDefault();

        const message = document.getElementById('name-2').value;
        const encryptionType = encryptionHiddenInput.value;
        const encryptKey = document.getElementById('name-3').value;

        const formData = new URLSearchParams();
        formData.append('message', message);
        formData.append('encryptionType', encryptionType);
        formData.append('encryptKey', encryptKey);

        fetch('/encrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData.toString(),
        })
            .then((response) => response.json())
            .then((data) => {
                encryptionForm.querySelector('textarea').value = data.encryptedMessage;
            })
            .catch(() => {
                alert('Encryption failed');
            });
    });

    //DECRYPT FORM
    const decryptionForm = document.querySelector('form:not([action])');
    decryptionForm.addEventListener('submit', function (e) {
        e.preventDefault();

        const encryptedMessage = document.getElementById('name-4').value;
        const decryptionType = decryptionHiddenInput.value;
        const decryptKey = document.getElementById('name-5').value;

        const formData = new URLSearchParams();
        formData.append('encryptedMessage', encryptedMessage);
        formData.append('decryptionType', decryptionType);
        formData.append('decryptKey', decryptKey);

        fetch('/decrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData.toString(),
        })
            .then((response) => response.json())
            .then((data) => {
                decryptionForm.querySelector('textarea').value = data.decryptedMessage;
            })
            .catch(() => {
                alert('Decryption failed');
            });
    });
});