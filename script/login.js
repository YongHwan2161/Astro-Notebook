const gnbLogin = document.querySelector("#gnb-login");
const btnLogin = document.querySelector("#btn-login");
const modalPopupClose = document.querySelector("#modal-popup-close");
const loginPopup = document.querySelector("#login-popup");
const loginModal = document.querySelector("#login-modal")

gnbLogin.addEventListener("click", ()=>{
  loginPopup.style.display = "flex";
  loginModal.style.display = "flex";
})

modalPopupClose.addEventListener("click", ()=>{
  loginPopup.style.display = "none";
  loginModal.style.display = "none";
})

btnLogin.addEventListener("click", ()=>{
  loginPopup.style.display = "flex";
  loginModal.style.display = "flex";
})