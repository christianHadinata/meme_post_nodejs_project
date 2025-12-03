const fileInput = document.getElementById("imageInput");
const previewArea = document.getElementById("previewArea");
const imgPreview = document.getElementById("imagePreview");
const placeholder = document.getElementById("placeholderText");
const submitBtn = document.getElementById("submitBtn");
const form = document.getElementById("uploadForm");
const captionInput = document.getElementById("captionInput");

previewArea.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) {
    const reader = new FileReader();
    reader.onload = (ev) => {
      imgPreview.src = ev.target.result;
      imgPreview.classList.remove("hidden");
      placeholder.classList.add("hidden");
      checkValidity();
    };
    reader.readAsDataURL(file);
  }
});

captionInput.addEventListener("input", checkValidity);

function checkValidity() {
  if (fileInput.files.length > 0 && captionInput.value.trim().length > 0) {
    submitBtn.disabled = false;
    submitBtn.style.opacity = 1;
  } else {
    submitBtn.disabled = true;
    submitBtn.style.opacity = 0.5;
  }
}

submitBtn.addEventListener("click", () => {
  form.submit();
});
