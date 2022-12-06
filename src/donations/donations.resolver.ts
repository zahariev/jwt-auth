import { Resolver, Query, Mutation, Args } from '@nestjs/graphql';
import { Prisma } from '@prisma/client';
import { Public } from 'src/common/decorators';
import { OrderByParams } from 'src/graphql';
import { DonationsService } from './donations.service';
import { UpdateDonationInput } from './dto/update-donation.input';

@Resolver('Donation')
export class DonationsResolver {
    constructor(private readonly donationsService: DonationsService) {}

    @Public()
    @Mutation('createDonation')
    create(@Args('createDonationInput') createDonationInput: Prisma.DonationCreateInput) {
        return this.donationsService.create(createDonationInput);
    }

    @Public()
    @Query('donations')
    findAll(@Args('orderBy') orderBy?: OrderByParams) {
        return this.donationsService.findAll(orderBy);
    }

    @Public()
    @Query('donation')
    findOne(@Args('id') id: number) {
        return this.donationsService.findOne(id);
    }

    @Mutation('updateDonation')
    update(@Args('updateDonationInput') updateDonationInput: UpdateDonationInput) {
        return this.donationsService.update(updateDonationInput.id, updateDonationInput);
    }

    @Mutation('removeDonation')
    remove(@Args('id') id: number) {
        return this.donationsService.remove(id);
    }
}