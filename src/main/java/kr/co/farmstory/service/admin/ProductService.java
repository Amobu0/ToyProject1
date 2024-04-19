package kr.co.farmstory.service.admin;

import kr.co.farmstory.dto.ProductDTO;
import kr.co.farmstory.entity.Product;
import kr.co.farmstory.repository.admin.ProductRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.coobird.thumbnailator.Thumbnails;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Transactional
@RequiredArgsConstructor
@Service
public class ProductService {

    private final ProductRepository repository;

    @Value("${images.upload.path}")
    private String imagesUploadPath;

    public void save(ProductDTO productDTO) {

        // 기본정보 이미지 , 상품설명 이미지 리스트
        List<MultipartFile> imgList = List.of(
                productDTO.getImage2(),
                productDTO.getImage3());
        //사진 업로드 시스템 경로 설정 (절대경로)
        //new FILE()  --> import java.io.File;

        String savePath = new File(imagesUploadPath).getAbsolutePath();

        // 썸네일로 저장할 첫번째 MultipartFile 가져오기
        MultipartFile thumbImg = productDTO.getImage1();
        Product product = productDTO.toEntity();
        if (thumbImg != null) {

            // thumbNail 사진의 원래 이름 앞에 넣는 랜덤 식별자 생성
            UUID uuid = UUID.randomUUID();

            //MultipartFile 원래 이름 가져오기
            String oriName = thumbImg.getOriginalFilename();

            // "s_" + uuid + _ + 사진의 원래 이름 = db에 저장되는 thumbNail 이름
            String thumbImageName = "s_" + uuid + "_" + oriName;
            product.setImage1(thumbImageName);

            // 임의의 파일 객체 생성
            File thumbFile = new File(savePath, thumbImageName);

            try {
                //썸네일 생성
                Thumbnails.of(thumbImg.getInputStream())
                        .size(140, 140)
                        .toFile(thumbFile);

            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        List<String> saveImageNames = new ArrayList<>();
        // 기본정보 이미지 , 상품설명 이미지 반복문으로 저장하기
        for (MultipartFile img : imgList) {

            // 사진의 원래 이름 앞에 넣는 랜덤 식별자 생성
            UUID uuid = UUID.randomUUID();

            // uuid + _ + 사진의 원래 이름 = db에 저장될 이름
            String saveImageName = uuid + "_" + img.getOriginalFilename();

            //사진 객체를 생성할 것인데 경로는 savePath, 이름은 saveImageName
            File saveFile = new File(savePath, saveImageName);

            //사진 저장
            try {
                img.transferTo(saveFile);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            saveImageNames.add(saveImageName);

        }
        product.setImage2(saveImageNames.get(0));
        product.setImage3(saveImageNames.get(1));

        repository.save(product);
    }

    public List<ProductDTO> prodFindAll() {

        List<ProductDTO> productDTOList = new ArrayList<>();
        List<Product> productList = repository.findAll();

        for (Product product : productList) {
            ProductDTO productDTO = product.toDTO();
            productDTOList.add(productDTO);
        }
        return productDTOList;
    }
}
