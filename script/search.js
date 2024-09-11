//click event - categories
/*
const freeSubject = document.querySelector("#free-subject")
const astronomy = document.querySelector("#astronomy")
const astroPhotoMovie = document.querySelector("#astro-photo-movie")
const request = document.querySelector("#request")
const recuitment = document.querySelector("#recuitment")

function btnrtgclick() {
  const currentColor = freeSubject.style.backgroundColor;
  let newColor;
  if(currentColor === "rgb(54, 144, 255)") {
    newColor = "rgb(230, 230, 230)";
  } else {
    newColor = "rgb(54, 144, 255)";
  }
  freeSubject.style.backgroundColor = newColor;
}

freeSubject.addEventListener("click", btnrtgclick);
*/

//click event - search
const btnSearchFilterOpen = document.querySelector("#btn-search-filter-open");
const btnSearchFilterClose = document.querySelector("#btn-search-filter-close");
const searchFilter = document.querySelector(".search-filter");

btnSearchFilterOpen.addEventListener("click", ()=>{
  btnSearchFilterOpen.style.display = "none"
  btnSearchFilterClose.style.display = "flex"
  searchFilter.style.display = "flex"
})

btnSearchFilterClose.addEventListener("click", ()=>{
  btnSearchFilterOpen.style.display = "flex"
  btnSearchFilterClose.style.display = "none"
  searchFilter.style.display = "none"
})