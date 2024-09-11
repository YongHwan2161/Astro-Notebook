const gnbMenu = document.querySelector("#gnb-menu");
const gnbClose = document.querySelector("#gnb-close");
const sideNav = document.querySelector(".side-nav");
const mainBannerText = document.querySelector("#main-banner-text");
gnbMenu.addEventListener("click", ()=>{
  sideNav.style.display = "flex";
  mainBannerText.style.display = "none";
})

gnbClose.addEventListener("click", ()=>{
  sideNav.style.display = "none";
  mainBannerText.style.display = "flex";
})
