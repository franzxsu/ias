console.log("gasdasda")

document.addEventListener('DOMContentLoaded', function() {
    const dropdownItems = document.querySelectorAll('.dropdown-item');
    const dropdownToggle = document.querySelector('.dropdown-toggle');
    const encryptionTypeInput = document.getElementById('encryptionType');

    dropdownItems.forEach(item => {
        item.addEventListener('click', function() {
            dropdownToggle.textContent = this.textContent;
            encryptionTypeInput.value = this.getAttribute('data-value');
        });
    });

// form
    const form = document.querySelector('form');
    form.addEventListener('submit', function(e) {
        e.preventDefault();

        const message = document.getElementById('name-2').value;
        const encryptionType = dropdownToggle.textContent;
        const encryptKey = document.getElementById('name-3').value;
        console.log(message);
        console.log(encryptionType);
        console.log(encryptKey);

        const formData = new URLSearchParams();
        formData.append('message', message);
        formData.append('encryptionType', encryptionType);
        formData.append('encryptKey', encryptKey);

        console.log(formData);

        fetch('/encrypt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData.toString()
        })
        .then(response => response.json())
        .then(data => {
            document.querySelector('textarea').value = data.encryptedMessage;
        })
        .catch(() => {
            alert('encryption failed');
        });
    });
});