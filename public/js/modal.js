const modal = document.getElementById("postModal");
const modalImg = document.getElementById("modalImg");
const modalCaption = document.getElementById("modalCaption");
const modalLikes = document.getElementById("modalLikes");
const modalAuthor = document.getElementById("modalAuthor");
const btnDelete = document.getElementById("btnDelete");
const closeBtn = document.querySelector(".modal-close");

function openModal(id, imageUrl, caption, likes, username, isAdmin) {
  modal.style.display = "block";
  modalImg.src = imageUrl;
  modalCaption.textContent = caption;
  modalLikes.textContent = likes + " Likes";
  modalAuthor.textContent = "Posted by: " + username;

  btnDelete.onclick = null;

  if (isAdmin) {
    btnDelete.classList.remove("hidden");
    btnDelete.onclick = function () {
      if (confirm("Apakah Anda yakin ingin menghapus post ini secara permanen?")) {
        deletePost(id);
      }
    };
  } else {
    btnDelete.classList.add("hidden");
  }
}

function handlePostClick(element) {
  const id = element.dataset.id;
  const imgUrl = element.dataset.img;
  const caption = element.dataset.caption;
  const likes = element.dataset.likes;
  const username = element.dataset.username;

  const isAdmin = element.dataset.isadmin === "true";

  openModal(id, imgUrl, caption, likes, username, isAdmin);
}

async function deletePost(postId) {
  try {
    const response = await fetch("/api/post/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ postId: postId }),
    });

    if (response.ok) {
      alert("Post berhasil dihapus!");
      window.location.reload();
    } else {
      alert("Gagal menghapus post.");
    }
  } catch (err) {
    console.error(err);
    alert("Terjadi kesalahan server.");
  }
}

closeBtn.onclick = function () {
  modal.style.display = "none";
};
window.onclick = function (event) {
  if (event.target == modal) modal.style.display = "none";
};
