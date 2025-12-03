async function toggleLike(svgElement, postId) {
  try {
    const response = await fetch("/api/like", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ postId: postId }),
    });

    if (response.status === 401) {
      alert("Silakan Login terlebih dahulu untuk me-like post!");
      window.location.href = "/login";
      return;
    }

    const data = await response.json();

    if (data.success) {
      const countSpan = document.getElementById(`likes-count-${postId}`);
      countSpan.innerText = `${data.likes} Likes`;

      if (data.isLiked) {
        svgElement.classList.add("like-active");
      } else {
        svgElement.classList.remove("like-active");
      }
    }
  } catch (err) {
    console.error("Error liking post:", err);
  }
}
